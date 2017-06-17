package com.github.xaanit.d4j.oauth.handle.impl;

import com.github.xaanit.d4j.oauth.Scope;
import com.github.xaanit.d4j.oauth.handle.IDiscordOAuth;
import com.github.xaanit.d4j.oauth.handle.IOAuthUser;
import com.github.xaanit.d4j.oauth.handle.IOAuthWebhook;
import com.github.xaanit.d4j.oauth.handle.impl.events.OAuthUserAuthorized;
import com.github.xaanit.d4j.oauth.internal.json.objects.AuthorizeUserResponse;
import org.apache.http.message.BasicNameValuePair;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.GitHubTokenResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.eclipse.jetty.util.MultiMap;
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
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class DiscordOAuth implements IDiscordOAuth {
	private final String clientID;
	private final String clientSecret;
	private final Scope[] scopes;
	private final String redirectUrl;
	private final IDiscordClient client;
	private final Cache<IOAuthUser> oauthUserCache;
	private final Cache<IOAuthWebhook> webhooks;

	public DiscordOAuth(IDiscordClient client, Scope[] scopes, String clientID, String clientSecret, String redirectUrl,
			String redirectPath) {
		this.clientID = clientID;
		this.clientSecret = clientSecret;
		this.scopes = scopes;
		this.client = client;
		this.redirectUrl = redirectUrl;
		this.oauthUserCache = new Cache<>((DiscordClientImpl) client, IOAuthUser.class);
		this.webhooks = new Cache<>((DiscordClientImpl) client, IOAuthWebhook.class);
	}

	public void onOAuthRequest(MultiMap<String> params, Runnable onFail, Consumer<IOAuthUser> onSuccess) {
		if (params.containsKey("error")) {
			Discord4J.LOGGER.error("Error! " + params.get("error"));
			onFail.run();
		} else if (params.containsKey("code")) {
			try {
				OAuthClientRequest request = OAuthClientRequest.tokenLocation(DiscordEndpoints.OAUTH + "token")
						.setGrantType(GrantType.AUTHORIZATION_CODE).setClientId(clientID).setClientSecret(clientSecret)
						.setRedirectURI(redirectUrl).setCode(params.getString("code")).buildQueryMessage();

				// create OAuth client that uses custom http client under the hood
				OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());

				// Facebook is not fully compatible with OAuth 2.0 draft 10, access token response is
				// application/x-www-form-urlencoded, not json encoded so we use dedicated response class for that
				// Custom response classes are an easy way to deal with oauth providers that introduce modifications to
				// OAuth 2.0 specification
				GitHubTokenResponse oAuthResponse = oAuthClient.accessToken(request, GitHubTokenResponse.class);

				String accessToken = oAuthResponse.getAccessToken();
				Long expiresIn = oAuthResponse.getExpiresIn();
				if (accessToken == null || expiresIn == null) {
					onFail.run();
					return;
				}
				Discord4J.LOGGER.debug("OAuth token received");

				/*
				 * OAuthClientRequest bearerClientRequest = new OAuthBearerClientRequest(DiscordEndpoints.USERS + "@me") .setAccessToken(accessToken).buildQueryMessage(); OAuthResourceResponse
				 * resourceResponse = oAuthClient.resource(bearerClientRequest, OAuth.HttpMethod.GET, OAuthResourceResponse.class);
				 */

				RequestBuffer.request(() -> {
					IUser user = DiscordUtils.getUserFromJSON(client.getShards().get(0),
							Requests.GENERAL_REQUESTS.GET.makeRequest(DiscordEndpoints.USERS + "@me", UserObject.class,
									new BasicNameValuePair("Authorization", "Bearer " + accessToken)));
					AuthorizeUserResponse auth = new AuthorizeUserResponse();
					auth.access_token = accessToken;
					auth.expires_in = expiresIn;
					auth.refresh_token = oAuthResponse.getRefreshToken();
					auth.scope = oAuthResponse.getScope();
					auth.token_type = oAuthResponse.getTokenType();
					IOAuthUser oauth = addOAuthUser(user, auth);

					onSuccess.accept(oauth);
					client.getDispatcher().dispatch(new OAuthUserAuthorized(oauth));
				});
			} catch (OAuthSystemException | OAuthProblemException e) {
				e.printStackTrace();
			}
		}
	}// The user did a thing!

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
			OAuthClientRequest req = OAuthClientRequest.authorizationLocation(DiscordEndpoints.APIBASE)
					.setClientId(clientID).setRedirectURI(redirectUrl)
					.setScope(Arrays.stream(scopes).map(Scope::getName).collect(Collectors.joining(" ")))
					.buildQueryMessage();
			return req.getLocationUri();
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
