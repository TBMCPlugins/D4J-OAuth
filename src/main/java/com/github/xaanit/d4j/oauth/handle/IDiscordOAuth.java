package com.github.xaanit.d4j.oauth.handle;

import com.github.xaanit.d4j.oauth.Scope;
import sx.blah.discord.api.IDiscordClient;
import sx.blah.discord.handle.obj.IUser;

import java.util.List;

public interface IDiscordOAuth {

	String getClientID();

	String getClientSecret();

	/**
	 * Builds the AuthURL to send to the user with the default scopes.
	 *
	 * @return The AuthURl
	 */
	String buildAuthUrl();

	/**
	 * Builds the AuthURL to send to the user.
	 *
	 * @param scopes The scopes to use
	 * @return The AuthURl
	 */
	String buildAuthUrl(Scope[] scopes);

	IOAuthUser getOAuthUser(IUser user);

	IOAuthUser getOAuthUserForID(long id);

	IOAuthUser getOAuthUserForRefreshToken(String refreshToken);

	List<IOAuthWebhook> getWebhooks();

	IOAuthWebhook getWebhookByID(long id);

	/**
	 * Gets the {@link IDiscordClient} client instance.
	 *
	 * @return The client
	 */
	IDiscordClient getClient();
}
