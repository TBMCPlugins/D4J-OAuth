package com.github.xaanit.d4j.oauth.handle.impl;

import com.github.xaanit.d4j.oauth.Scope;
import com.github.xaanit.d4j.oauth.handle.IDiscordOAuth;
import com.github.xaanit.d4j.oauth.handle.IOAuthUser;
import com.github.xaanit.d4j.oauth.handle.IOAuthWebhook;
import com.github.xaanit.d4j.oauth.handle.impl.events.OAuthUserAuthorized;
import com.github.xaanit.d4j.oauth.handle.impl.events.OAuthWebhookCreate;
import com.github.xaanit.d4j.oauth.internal.json.objects.AuthorizeUserResponse;
import org.apache.http.message.BasicNameValuePair;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;

import sx.blah.discord.Discord4J;
import sx.blah.discord.api.IDiscordClient;
import sx.blah.discord.api.internal.DiscordClientImpl;
import sx.blah.discord.api.internal.DiscordEndpoints;
import sx.blah.discord.api.internal.DiscordUtils;
import sx.blah.discord.api.internal.Requests;
import sx.blah.discord.api.internal.json.objects.UserObject;
import sx.blah.discord.handle.obj.IUser;
import sx.blah.discord.util.RequestBuffer;
import sx.blah.discord.util.cache.Cache;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class DiscordOAuth implements IDiscordOAuth {
	private final String clientID;
	private final String clientSecret;
	private final Scope[] scopes;
	private final String redirectUrl;
	private final IDiscordClient client;
	private final OAuthClientRequest oauth2Auth;
	private final Cache<IOAuthUser> oauthUserCache;
	private final Cache<IOAuthWebhook> webhooks;

	public DiscordOAuth(IDiscordClient client, Scope[] scopes, String clientID, String clientSecret, String redirectUrl,
			String redirectPath, Runnable onFail, Consumer<IOAuthUser> onSuccess) {
		this.clientID = clientID;
		this.clientSecret = clientSecret;
		this.scopes = scopes;
		this.client = client;
		this.redirectUrl = redirectUrl;
		this.oauthUserCache = new Cache<>((DiscordClientImpl) client, IOAuthUser.class);
		this.webhooks = new Cache<>((DiscordClientImpl) client, IOAuthWebhook.class);

		oauth2Auth = OAuthClientRequest.authorizationLocation(DiscordEndpoints.APIBASE).setClientId(clientID)
				.setRedirectURI(redirectUrl).setScope(scopes);

		router.get(redirectPath).handler(context -> {
			MultiMap params = context.request().params();
			if (params.contains("error")) {
				Discord4J.LOGGER.error("Error! " + params.get("error"));
				onFail.accept(context);
			} else if (params.contains("code")) {
				oauth2Auth.getToken(new JsonObject().put("code", params.get("code")).put("redirect_uri", redirectUrl),
						res -> {
							if (res.failed()) {
								Discord4J.LOGGER.error("Result failed!");
								res.cause().printStackTrace();
								onFail.accept(context);
							} else {
								AuthorizeUserResponse authorize = res.result().principal()
										.mapTo(AuthorizeUserResponse.class);
								Discord4J.LOGGER.debug("OAuth token received");

								if (authorize.webhook != null) {
									RequestBuffer.request(() -> {
										IUser user = DiscordUtils.getUserFromJSON(client.getShards().get(0),
												Requests.GENERAL_REQUESTS.GET.makeRequest(
														DiscordEndpoints.USERS + "@me", UserObject.class,
														new BasicNameValuePair("Authorization",
																"Bearer " + authorize.access_token)));
										IOAuthUser oauth = addOAuthUser(user, authorize);

										IOAuthWebhook webhook = new OAuthWebhook(authorize.webhook, oauth);
										webhooks.put(webhook);

										onSuccess.accept(context, oauth);
										client.getDispatcher().dispatch(new OAuthUserAuthorized(oauth));
										client.getDispatcher().dispatch(new OAuthWebhookCreate(webhook));
									});
								} else {
									RequestBuffer.request(() -> {
										IUser user = DiscordUtils.getUserFromJSON(client.getShards().get(0),
												Requests.GENERAL_REQUESTS.GET.makeRequest(
														DiscordEndpoints.USERS + "@me", UserObject.class,
														new BasicNameValuePair("Authorization",
																"Bearer " + authorize.access_token)));
										IOAuthUser oauth = addOAuthUser(user, authorize);

										onSuccess.accept(context, oauth);
										client.getDispatcher().dispatch(new OAuthUserAuthorized(oauth));
									});
								}
							}
						});
			}
		}); // The user did a thing!

		server.requestHandler(router::accept);
		server.listen();
	}

	@Override
	public String getClientID() {
		return clientID;
	}

	@Override
	public String getClientSecret() {
		return clientSecret;
	}

	public String buildAuthUrl() {
		return buildAuthUrl(scopes);
	}

	public String buildAuthUrl(Scope[] scopes) {
		try {
			return oauth2Auth.authorizeURL(new JsonObject().put("redirect_uri", redirectUrl).put("scopes",
					new JsonArray(Arrays.stream(scopes).map(Scope::getName).collect(Collectors.toList()))));
		} catch (Throwable th) {
			th.printStackTrace();
		}
		return "";
	}

	@Override
	public IOAuthUser getOAuthUser(IUser user) {
		return !oauthUserCache.containsKey(user.getLongID()) ? null : oauthUserCache.get(user.getLongID());
	}

	@Override
	public IOAuthUser getOAuthUserForID(long id) {
		return !oauthUserCache.containsKey(id) ? null : oauthUserCache.get(id);
	}

	@Override
	public IOAuthUser getOAuthUserForRefreshToken(String refreshToken) {
		AuthorizeUserResponse authorize = Requests.GENERAL_REQUESTS.POST.makeRequest(DiscordEndpoints.OAUTH + "token",
				String.format("grant_type=refresh_token&refresh_token=%s&client_id=%s&client_secret=%s", refreshToken,
						clientID, clientSecret),
				AuthorizeUserResponse.class,
				new BasicNameValuePair("Content-Type", "application/x-www-form-urlencoded"));
		IUser user = DiscordUtils.getUserFromJSON(client.getShards().get(0),
				Requests.GENERAL_REQUESTS.GET.makeRequest(DiscordEndpoints.USERS + "@me", UserObject.class,
						new BasicNameValuePair("Authorization", "Bearer " + authorize.access_token)));
		return addOAuthUser(user, authorize);
	}

	@Override
	public List<IOAuthWebhook> getWebhooks() {
		return new LinkedList<>(webhooks.values());
	}

	@Override
	public IOAuthWebhook getWebhookByID(long id) {
		return !webhooks.containsKey(id) ? null : webhooks.get(id);
	}

	@Override
	public IDiscordClient getClient() {
		return client;
	}

	public IOAuthUser addOAuthUser(IUser user, AuthorizeUserResponse authorize) {
		if (oauthUserCache.containsKey(user.getLongID())) {
			OAuthUser oauth = (OAuthUser) oauthUserCache.get(user.getLongID());
			oauth.updateToken(authorize.access_token, authorize.expires_at);
			return oauth;
		} else {
			IOAuthUser oauth = new OAuthUser(this, user, authorize.access_token, authorize.refresh_token, 0,
					Scope.getScopes(authorize.scope));
			oauthUserCache.put(oauth);
			return oauth;
		}
	}
}
