import type { GenericEndpointContext } from "@better-auth/core";
import { APIError } from "better-auth/api";
import { generateRandomString } from "better-auth/crypto";
import { generateCodeChallenge } from "better-auth/oauth2";
import { signJWT, toExpJWT } from "better-auth/plugins";
import type { Session, User } from "better-auth/types";
import type { JWTPayload } from "jose";
import { SignJWT } from "jose";
import type {
	ActorTokenExhangeType,
	OAuthOptions,
	OAuthRefreshToken,
	RequestedTokenExhangeType,
	SchemaClient,
	Scope,
	SubjectTokenExhangeType,
	VerificationValue,
} from "./types";
import type { GrantType, TokenTypeIdentifier } from "./types/oauth";
import { userNormalClaims } from "./userinfo";
import {
	basicToClientCredentials,
	decryptStoredClientSecret,
	getJwtPlugin,
	getStoredToken,
	isPKCERequired,
	parseClientMetadata,
	resolveSubjectIdentifier,
	storeToken,
	validateClientCredentials,
} from "./utils";
import { validateAccessToken, validateIdToken } from "./introspect";

/**
 * Handles the /oauth2/token endpoint by delegating
 * the grant types
 */
export async function tokenEndpoint(
	ctx: GenericEndpointContext,
	opts: OAuthOptions<Scope[]>,
) {
	const grantType: GrantType | undefined = ctx.body?.grant_type;

	if (opts.grantTypes && grantType && !opts.grantTypes.includes(grantType)) {
		throw new APIError("BAD_REQUEST", {
			error_description: `unsupported grant_type ${grantType}`,
			error: "unsupported_grant_type",
		});
	}

	switch (grantType) {
		case "authorization_code":
			return handleAuthorizationCodeGrant(ctx, opts);
		case "client_credentials":
			return handleClientCredentialsGrant(ctx, opts);
		case "refresh_token":
			return handleRefreshTokenGrant(ctx, opts);
		case "urn:ietf:params:oauth:grant-type:token-exchange":
			return handleTokenExchangeGrant(ctx, opts);
		default:
			throw new APIError("BAD_REQUEST", {
				error_description: `unsupported grant_type ${grantType}`,
				error: "unsupported_grant_type",
			});
	}
}

// User Jwt SHALL follow oAuth 2
// NOTE: Requires jwt plugin (assert !opts.disableJwtPlugin)
async function createJwtAccessToken(
	ctx: GenericEndpointContext,
	opts: OAuthOptions<Scope[]>,
	user: User,
	client: SchemaClient<Scope[]>,
	audience: string | string[],
	scopes: string[],
	referenceId?: string,
	overrides?: {
		iat?: number;
		exp?: number;
		sid?: string;
	},
) {
	const iat = overrides?.iat ?? Math.floor(Date.now() / 1000);
	const exp = overrides?.exp ?? iat + (opts.accessTokenExpiresIn ?? 3600);
	const customClaims = opts.customAccessTokenClaims
		? await opts.customAccessTokenClaims({
				user,
				scopes,
				resource: ctx.body.resource,
				referenceId,
				metadata: parseClientMetadata(client.metadata),
			})
		: {};

	const jwtPluginOptions = getJwtPlugin(ctx.context).options;

	// Sign token
	return signJWT(ctx, {
		options: jwtPluginOptions,
		payload: {
			...customClaims,
			sub: user.id,
			aud:
				typeof audience === "string"
					? audience
					: audience?.length === 1
						? audience.at(0)
						: audience,
			azp: client.clientId,
			scope: scopes.join(" "),
			sid: overrides?.sid,
			iss: jwtPluginOptions?.jwt?.issuer ?? ctx.context.baseURL,
			iat,
			exp,
		},
	});
}

/**
 * Creates a user id token in code_authorization with scope of 'openid'
 * and hybrid/implicit (not yet implemented) flows
 */
async function createIdToken(
	ctx: GenericEndpointContext,
	opts: OAuthOptions<Scope[]>,
	user: User,
	client: SchemaClient<Scope[]>,
	scopes: string[],
	nonce?: string,
	sessionId?: string,
	authTime?: Date,
) {
	const iat = Math.floor(Date.now() / 1000);
	const exp = iat + (opts.idTokenExpiresIn ?? 36000);
	const userClaims = userNormalClaims(user, scopes);
	const resolvedSub = await resolveSubjectIdentifier(user.id, client, opts);
	const authTimeSec =
		authTime != null ? Math.floor(authTime.getTime() / 1000) : undefined;
	// TODO: this should be validated against the login process
	// - bronze : password only
	// - silver : mfa
	const acr = "urn:mace:incommon:iap:bronze";

	const customClaims = opts.customIdTokenClaims
		? await opts.customIdTokenClaims({
				user,
				scopes,
				metadata: parseClientMetadata(client.metadata),
			})
		: {};

	const jwtPluginOptions = opts.disableJwtPlugin
		? undefined
		: getJwtPlugin(ctx.context).options;

	const payload: JWTPayload = {
		...userClaims,
		...customClaims,
		auth_time: authTimeSec,
		acr,
		iss: jwtPluginOptions?.jwt?.issuer ?? ctx.context.baseURL,
		sub: resolvedSub,
		aud: client.clientId,
		nonce,
		iat,
		exp,
		sid: client.enableEndSession ? sessionId : undefined,
	};

	// Public clients without a client secret cannot receive an idToken as it can't be verified
	// Confidential clients would still receive an idToken signed by the clientSecret
	if (opts.disableJwtPlugin && !client.clientSecret) {
		return undefined;
	}

	return opts.disableJwtPlugin
		? new SignJWT(payload)
				.setProtectedHeader({ alg: "HS256" })
				.sign(
					new TextEncoder().encode(
						await decryptStoredClientSecret(
							ctx,
							opts.storeClientSecret,
							client.clientSecret!,
						),
					),
				)
		: signJWT(ctx, {
				options: jwtPluginOptions,
				payload,
			});
}

/**
 * Encodes a refresh token for a client
 */
async function encodeRefreshToken(
	opts: OAuthOptions<Scope[]>,
	token: string,
	sessionId?: string,
) {
	return (
		(opts.prefix?.refreshToken ?? "") +
		(opts.formatRefreshToken?.encrypt
			? opts.formatRefreshToken.encrypt(token, sessionId)
			: token)
	);
}

/**
 * Decodes a refresh token for a client
 *
 * @internal
 */
export async function decodeRefreshToken(
	opts: OAuthOptions<Scope[]>,
	token: string,
) {
	if (opts.prefix?.refreshToken) {
		if (token.startsWith(opts.prefix.refreshToken)) {
			token = token.replace(opts.prefix.refreshToken, "");
		} else {
			throw new APIError("BAD_REQUEST", {
				error_description: "refresh token not found",
				error: "invalid_token",
			});
		}
	}

	return opts.formatRefreshToken?.decrypt
		? opts.formatRefreshToken?.decrypt(token)
		: { token };
}

async function createOpaqueAccessToken(
	ctx: GenericEndpointContext,
	opts: OAuthOptions<Scope[]>,
	user: User | undefined,
	client: SchemaClient<Scope[]>,
	scopes: string[],
	payload: JWTPayload,
	referenceId?: string,
	refreshId?: string,
) {
	const iat = payload.iat ?? Math.floor(Date.now() / 1000);
	const exp = payload?.exp ?? iat + (opts.accessTokenExpiresIn ?? 3600);
	const token = opts.generateOpaqueAccessToken
		? await opts.generateOpaqueAccessToken()
		: generateRandomString(32, "A-Z", "a-z");
	await ctx.context.adapter.create({
		model: "oauthAccessToken",
		data: {
			token: await storeToken(opts.storeTokens, token, "access_token"),
			clientId: client.clientId,
			sessionId: payload?.sid,
			userId: user?.id,
			referenceId,
			refreshId,
			scopes,
			createdAt: new Date(iat * 1000),
			expiresAt: new Date(exp * 1000),
			act: payload.act,
		},
	});
	return (opts.prefix?.opaqueAccessToken ?? "") + token;
}

async function createRefreshToken(
	ctx: GenericEndpointContext,
	opts: OAuthOptions<Scope[]>,
	user: User,
	referenceId: string | undefined,
	client: SchemaClient<Scope[]>,
	scopes: string[],
	payload: JWTPayload,
	originalRefresh?: OAuthRefreshToken<Scope[]> & { id: string },
	authTime?: Date,
) {
	const iat = payload.iat ?? Math.floor(Date.now() / 1000);
	const exp = payload?.exp ?? iat + (opts.refreshTokenExpiresIn ?? 2592000);
	const token = opts.generateRefreshToken
		? await opts.generateRefreshToken()
		: generateRandomString(32, "A-Z", "a-z");
	const sessionId = payload?.sid as string | undefined;
	// Mark old refresh as stale
	if (originalRefresh?.id) {
		await ctx.context.adapter.update({
			model: "oauthRefreshToken",
			where: [
				{
					field: "id",
					value: originalRefresh.id,
				},
			],
			update: {
				revoked: new Date(iat * 1000),
			},
		});
	}

	// Issue new refresh token
	const refreshToken = await ctx.context.adapter.create({
		model: "oauthRefreshToken",
		data: {
			token: await storeToken(opts.storeTokens, token, "refresh_token"),
			clientId: client.clientId,
			sessionId,
			userId: user.id,
			referenceId,
			authTime,
			scopes,
			createdAt: new Date(iat * 1000),
			expiresAt: new Date(exp * 1000),
		},
	});
	return {
		id: refreshToken.id,
		token: await encodeRefreshToken(opts, token, sessionId),
	};
}

/**
 * Checks the resource parameter, if provided,
 * and returns a valid audience based on the request
 */
async function checkResource(
	ctx: GenericEndpointContext,
	opts: OAuthOptions<Scope[]>,
	scopes: string[],
) {
	const resource: string | string[] | undefined = ctx.body.resource;
	const audience =
		typeof resource === "string"
			? [resource]
			: resource
				? [...resource]
				: undefined;
	if (audience) {
		// Adds /userinfo to audience
		if (scopes.includes("openid")) {
			audience.push(`${ctx.context.baseURL}/oauth2/userinfo`);
		}
		// Check valid audiences
		const validAudiences = new Set(
			[
				...(opts.validAudiences ?? [ctx.context.baseURL]),
				scopes?.includes("openid")
					? `${ctx.context.baseURL}/oauth2/userinfo`
					: undefined,
			]
				.flat()
				.filter((v) => v?.length),
		);
		for (const aud of audience) {
			if (!validAudiences.has(aud)) {
				throw new APIError("BAD_REQUEST", {
					error_description: "requested resource invalid",
					error: "invalid_request",
				});
			}
		}
	}
	return audience?.length === 1 ? audience.at(0) : audience;
}

async function createUserTokens(
	ctx: GenericEndpointContext,
	opts: OAuthOptions<Scope[]>,
	client: SchemaClient<Scope[]>,
	scopes: string[],
	user: User,
	referenceId?: string,
	sessionId?: string,
	nonce?: string,
	additional?: {
		refreshToken?: OAuthRefreshToken<Scope[]> & { id: string };
	},
	authTime?: Date,
) {
	const iat = Math.floor(Date.now() / 1000);
	const defaultExp = iat + (opts.accessTokenExpiresIn ?? 3600);
	const exp = opts.scopeExpirations
		? scopes
				.map((sc) =>
					opts.scopeExpirations?.[sc]
						? toExpJWT(opts.scopeExpirations[sc], iat)
						: defaultExp,
				)
				.reduce((prev, curr) => {
					return prev < curr ? prev : curr;
				}, defaultExp)
		: defaultExp;

	// Check requested audience if sent as the resource parameter
	const audience = await checkResource(ctx, opts, scopes);
	const isRefreshToken =
		additional?.refreshToken?.scopes?.includes("offline_access") ||
		scopes.includes("offline_access");
	const isJwtAccessToken = audience && !opts.disableJwtPlugin;
	const isIdToken = scopes.includes("openid");

	// Refresh token may need to be created beforehand for id field
	const earlyRefreshToken =
		isRefreshToken && !isJwtAccessToken
			? await createRefreshToken(
					ctx,
					opts,
					user,
					referenceId,
					client,
					scopes,
					{
						iat,
						exp: iat + (opts.refreshTokenExpiresIn ?? 2592000),
						sid: sessionId,
					},
					additional?.refreshToken,
					authTime,
				)
			: undefined;

	// Sign jwt and refresh tokens in parallel
	const [accessToken, refreshToken, idToken] = await Promise.all([
		isJwtAccessToken
			? createJwtAccessToken(
					ctx,
					opts,
					user,
					client,
					audience,
					scopes,
					referenceId,
					{
						iat,
						exp,
						sid: sessionId,
					},
				)
			: createOpaqueAccessToken(
					ctx,
					opts,
					user,
					client,
					scopes,
					{
						iat,
						exp,
						sid: sessionId,
					},
					referenceId,
					earlyRefreshToken?.id,
				),
		earlyRefreshToken
			? earlyRefreshToken
			: isRefreshToken
				? createRefreshToken(
						ctx,
						opts,
						user,
						referenceId,
						client,
						scopes,
						{
							iat,
							exp: iat + (opts.refreshTokenExpiresIn ?? 2592000),
							sid: sessionId,
						},
						additional?.refreshToken,
						authTime,
					)
				: undefined,
		isIdToken
			? createIdToken(
					ctx,
					opts,
					user,
					client,
					scopes,
					nonce,
					sessionId,
					authTime,
				)
			: undefined,
	]);

	return ctx.json(
		{
			access_token: accessToken,
			expires_in: exp - iat,
			expires_at: exp,
			token_type: "Bearer",
			refresh_token: refreshToken?.token,
			scope: scopes.join(" "),
			id_token: idToken,
		},
		{
			headers: {
				"Cache-Control": "no-store",
				Pragma: "no-cache",
			},
		},
	);
}

/** Checks verification value */
async function checkVerificationValue(
	ctx: GenericEndpointContext,
	opts: OAuthOptions<Scope[]>,
	code: string,
	client_id: string,
	redirect_uri?: string,
) {
	const verification = await ctx.context.internalAdapter.findVerificationValue(
		await storeToken(opts.storeTokens, code, "authorization_code"),
	);
	const verificationValue: VerificationValue = verification
		? JSON.parse(verification?.value)
		: undefined;

	if (!verification) {
		throw new APIError("UNAUTHORIZED", {
			error_description: "Invalid code",
			error: "invalid_verification",
		});
	}

	// Delete used code
	await ctx.context.internalAdapter.deleteVerificationByIdentifier(
		await storeToken(opts.storeTokens, code, "authorization_code"),
	);

	// Check verification
	if (!verification.expiresAt || verification.expiresAt < new Date()) {
		throw new APIError("UNAUTHORIZED", {
			error_description: "code expired",
			error: "invalid_verification",
		});
	}

	// Check verification value
	if (!verificationValue) {
		throw new APIError("UNAUTHORIZED", {
			error_description: "missing verification value content",
			error: "invalid_verification",
		});
	}
	if (verificationValue.type !== "authorization_code") {
		throw new APIError("UNAUTHORIZED", {
			error_description: "incorrect verification type",
			error: "invalid_verification",
		});
	}
	if (verificationValue.query.client_id !== client_id) {
		throw new APIError("UNAUTHORIZED", {
			error_description: "invalid client_id",
			error: "invalid_client",
		});
	}
	if (!verificationValue.userId) {
		throw new APIError("BAD_REQUEST", {
			error_description: "missing user_id on challenge",
			error: "invalid_user",
		});
	}
	if (
		verificationValue.query?.redirect_uri &&
		verificationValue.query?.redirect_uri !== redirect_uri
	) {
		throw new APIError("BAD_REQUEST", {
			error_description: "missing verification redirect_uri",
			error: "invalid_request",
		});
	}

	return verificationValue;
}

/**
 * Obtains new Session Jwt and Refresh Tokens using a code
 */
async function handleAuthorizationCodeGrant(
	ctx: GenericEndpointContext,
	opts: OAuthOptions<Scope[]>,
) {
	let {
		client_id,
		client_secret,
		code,
		code_verifier,
		redirect_uri,
	}: {
		client_id?: string;
		client_secret?: string;
		code?: string;
		code_verifier?: string;
		redirect_uri?: string;
	} = ctx.body;
	const authorization = ctx.request?.headers.get("authorization") || null;

	// Convert basic authorization
	if (authorization?.startsWith("Basic ")) {
		const res = basicToClientCredentials(authorization);
		client_id = res?.client_id;
		client_secret = res?.client_secret;
	}

	if (!client_id) {
		throw new APIError("BAD_REQUEST", {
			error_description: "client_id is required",
			error: "invalid_request",
		});
	}
	if (!code) {
		throw new APIError("BAD_REQUEST", {
			error_description: "code is required",
			error: "invalid_request",
		});
	}
	if (!redirect_uri) {
		throw new APIError("BAD_REQUEST", {
			error_description: "redirect_uri is required",
			error: "invalid_request",
		});
	}

	const isAuthCodeWithSecret = client_id && client_secret;
	const isAuthCodeWithPkce = client_id && code && code_verifier;

	if (!isAuthCodeWithSecret && !isAuthCodeWithPkce) {
		throw new APIError("BAD_REQUEST", {
			error_description: "Either code_verifier or client_secret is required",
			error: "invalid_request",
		});
	}

	/** Get and check Verification Value */
	const verificationValue = await checkVerificationValue(
		ctx,
		opts,
		code,
		client_id,
		redirect_uri,
	);
	const scopes = verificationValue.query.scope?.split(" ");
	if (!scopes) {
		throw new APIError("INTERNAL_SERVER_ERROR", {
			error_description: "verification scope unset",
			error: "invalid_scope",
		});
	}

	/** Verify Client */
	const client = await validateClientCredentials(
		ctx,
		opts,
		client_id,
		client_secret,
		scopes,
	);

	// Parse scopes from the authorization request
	const requestedScopes =
		(verificationValue.query?.scope as string)?.split(" ") || [];

	// Check if PKCE is required for this client
	const pkceRequired = isPKCERequired(client, requestedScopes);

	// Validate credentials based on requirements
	if (pkceRequired) {
		// PKCE is required - must have code_verifier
		if (!isAuthCodeWithPkce) {
			throw new APIError("BAD_REQUEST", {
				error_description: "PKCE is required for this client",
				error: "invalid_request",
			});
		}
	} else {
		// PKCE is optional - must have either PKCE or client_secret
		if (!(isAuthCodeWithPkce || isAuthCodeWithSecret)) {
			throw new APIError("BAD_REQUEST", {
				error_description:
					"Either PKCE (code_verifier) or client authentication (client_secret) is required",
				error: "invalid_request",
			});
		}
	}

	/** Check PKCE challenge if verifier is provided */
	const pkceUsedInAuth = !!verificationValue.query?.code_challenge;
	const pkceUsedInToken = !!code_verifier;

	if (pkceUsedInAuth || pkceUsedInToken) {
		// PKCE was used - must verify consistency

		if (pkceUsedInAuth && !pkceUsedInToken) {
			// PKCE was used in authorization but not in token exchange
			throw new APIError("UNAUTHORIZED", {
				error_description:
					"code_verifier required because PKCE was used in authorization",
				error: "invalid_request",
			});
		}

		if (!pkceUsedInAuth && pkceUsedInToken) {
			// PKCE was not used in authorization but verifier provided
			throw new APIError("UNAUTHORIZED", {
				error_description:
					"code_verifier provided but PKCE was not used in authorization",
				error: "invalid_request",
			});
		}

		// Both sides used PKCE - verify the challenge
		const challenge =
			verificationValue.query?.code_challenge_method === "S256"
				? await generateCodeChallenge(code_verifier!)
				: undefined;

		if (challenge !== verificationValue.query?.code_challenge) {
			throw new APIError("UNAUTHORIZED", {
				error_description: "code verification failed",
				error: "invalid_request",
			});
		}
	}

	/** Get user */
	if (!verificationValue.userId) {
		throw new APIError("BAD_REQUEST", {
			error_description: "missing user, user may have been deleted",
			error: "invalid_user",
		});
	}
	const user = await ctx.context.internalAdapter.findUserById(
		verificationValue.userId,
	);
	if (!user) {
		throw new APIError("BAD_REQUEST", {
			error_description: "missing user, user may have been deleted",
			error: "invalid_user",
		});
	}

	// Check if session used is still active
	const session = await ctx.context.adapter.findOne<Session>({
		model: "session",
		where: [
			{
				field: "id",
				value: verificationValue.sessionId,
			},
		],
	});
	if (!session || session.expiresAt < new Date()) {
		throw new APIError("BAD_REQUEST", {
			error_description: "session no longer exists",
			error: "invalid_request",
		});
	}

	const authTime =
		verificationValue.authTime != null
			? new Date(verificationValue.authTime)
			: new Date(session.createdAt);

	return createUserTokens(
		ctx,
		opts,
		client,
		verificationValue.query.scope?.split(" ") ?? [],
		user,
		verificationValue.referenceId,
		session.id,
		verificationValue.query?.nonce,
		undefined,
		authTime,
	);
}

/**
 * Grant that allows direct access to an API using the application's credentials
 * This grant is for M2M so the concept of a user id does not exist on the token.
 *
 * MUST follow https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
 */
async function handleClientCredentialsGrant(
	ctx: GenericEndpointContext,
	opts: OAuthOptions<Scope[]>,
) {
	let {
		client_id,
		client_secret,
		scope,
	}: {
		client_id?: string;
		client_secret?: string;
		scope?: string;
	} = ctx.body;
	const authorization = ctx.request?.headers.get("authorization") || null;

	// Convert basic authorization
	if (authorization?.startsWith("Basic ")) {
		const res = basicToClientCredentials(authorization);
		client_id = res?.client_id;
		client_secret = res?.client_secret;
	}

	if (!client_id) {
		throw new APIError("BAD_REQUEST", {
			error_description: "Missing required client_id",
			error: "invalid_grant",
		});
	}
	if (!client_secret) {
		throw new APIError("BAD_REQUEST", {
			error_description: "Missing a required client_secret",
			error: "invalid_grant",
		});
	}

	// Note: Scope check is done below instead of through the function since different requirements
	const client = await validateClientCredentials(
		ctx,
		opts,
		client_id,
		client_secret,
	);

	// OIDC scopes should not be requestable (code authorization grant should be used)
	let requestedScopes = scope?.split(" ");
	if (requestedScopes) {
		const validScopes = new Set(client.scopes ?? opts.scopes);
		const oidcScopes = new Set([
			"openid",
			"profile",
			"email",
			"offline_access",
		]);
		const invalidScopes = requestedScopes.filter((scope) => {
			return !validScopes?.has(scope) || oidcScopes.has(scope);
		});
		if (invalidScopes.length) {
			throw new APIError("BAD_REQUEST", {
				error_description: `The following scopes are invalid: ${invalidScopes.join(", ")}`,
				error: "invalid_scope",
			});
		}
	}
	// Set default scopes to all those available for that client or all provided scopes.
	if (!requestedScopes) {
		requestedScopes =
			client.scopes ??
			opts.clientCredentialGrantDefaultScopes ??
			opts.scopes ??
			[];
	}

	// Check requested audience if sent as the resource parameter
	const jwtPluginOptions = opts.disableJwtPlugin
		? undefined
		: getJwtPlugin(ctx.context).options;
	const audience = await checkResource(ctx, opts, requestedScopes);

	const iat = Math.floor(Date.now() / 1000);
	const defaultExp = iat + (opts.m2mAccessTokenExpiresIn ?? 3600);
	const exp =
		opts.scopeExpirations && requestedScopes
			? requestedScopes
					.map((sc) =>
						opts.scopeExpirations?.[sc]
							? toExpJWT(opts.scopeExpirations[sc], iat)
							: defaultExp,
					)
					.reduce((prev, curr) => {
						return prev < curr ? prev : curr;
					}, defaultExp)
			: defaultExp;

	const customClaims = opts.customAccessTokenClaims
		? await opts.customAccessTokenClaims({
				scopes: requestedScopes,
				resource: ctx.body.resource,
				metadata: parseClientMetadata(client.metadata),
			})
		: {};

	const accessToken =
		audience && !opts.disableJwtPlugin
			? await signJWT(ctx, {
					options: jwtPluginOptions,
					payload: {
						...customClaims,
						aud: audience,
						azp: client.clientId,
						scope: requestedScopes.join(" "),
						iss: jwtPluginOptions?.jwt?.issuer ?? ctx.context.baseURL,
						iat,
						exp,
					},
				})
			: await createOpaqueAccessToken(
					ctx,
					opts,
					undefined,
					client,
					requestedScopes,
					{
						iat,
						exp,
					},
				);

	return ctx.json(
		{
			access_token: accessToken,
			expires_in: exp - iat,
			expires_at: exp,
			token_type: "Bearer",
			scope: requestedScopes.join(" "),
		},
		{
			headers: {
				"Cache-Control": "no-store",
				Pragma: "no-cache",
			},
		},
	);
}

/**
 * Obtains new Session Jwt and Refresh Tokens using a refresh token
 *
 * Refresh tokens will only allow the same or lesser scopes as the initial authorize request.
 * To add scopes, you must restart the authorize process again.
 */
async function handleRefreshTokenGrant(
	ctx: GenericEndpointContext,
	opts: OAuthOptions<Scope[]>,
) {
	let {
		client_id,
		client_secret,
		refresh_token,
		scope,
	}: {
		client_id?: string;
		client_secret?: string;
		refresh_token?: string;
		scope?: string;
	} = ctx.body;

	const authorization = ctx.request?.headers.get("authorization") || null;

	// Convert basic authorization
	if (authorization?.startsWith("Basic ")) {
		const res = basicToClientCredentials(authorization);
		client_id = res?.client_id;
		client_secret = res?.client_secret;
	}

	if (!client_id) {
		throw new APIError("BAD_REQUEST", {
			error_description: "Missing required client_id",
			error: "invalid_grant",
		});
	}

	if (!refresh_token) {
		throw new APIError("BAD_REQUEST", {
			error_description:
				"Missing a required refresh_token for refresh_token grant",
			error: "invalid_grant",
		});
	}
	const decodedRefresh = await decodeRefreshToken(opts, refresh_token);

	const refreshToken = await ctx.context.adapter.findOne<
		OAuthRefreshToken<Scope[]> & { id: string }
	>({
		model: "oauthRefreshToken",
		where: [
			{
				field: "token",
				value: await getStoredToken(
					opts.storeTokens,
					decodedRefresh.token,
					"refresh_token",
				),
			},
		],
	});

	// Check refresh
	if (!refreshToken) {
		throw new APIError("BAD_REQUEST", {
			error_description: "session not found",
			error: "invalid_grant",
		});
	}
	if (refreshToken.clientId !== client_id) {
		throw new APIError("BAD_REQUEST", {
			error_description: "invalid client_id",
			error: "invalid_client",
		});
	}
	if (refreshToken.expiresAt < new Date()) {
		throw new APIError("BAD_REQUEST", {
			error_description: "invalid refresh token",
			error: "invalid_grant",
		});
	}
	// Replay revoke (delete all tokens for that user-client)
	if (refreshToken.revoked) {
		await ctx.context.adapter.deleteMany({
			model: "oauthRefreshToken",
			where: [
				{
					field: "clientId",
					value: client_id,
				},
				{
					field: "userId",
					value: refreshToken.userId,
				},
			],
		});
		throw new APIError("BAD_REQUEST", {
			error_description: "invalid refresh token",
			error: "invalid_grant",
		});
	}

	// Check session scopes
	const scopes = refreshToken?.scopes;
	const requestedScopes = scope?.split(" ");
	if (requestedScopes) {
		const validScopes = new Set(scopes);
		for (const requestedScope of requestedScopes) {
			if (!validScopes.has(requestedScope)) {
				throw new APIError("BAD_REQUEST", {
					error_description: `unable to issue scope ${requestedScope}`,
					error: "invalid_scope",
				});
			}
		}
	}

	const client = await validateClientCredentials(
		ctx,
		opts,
		client_id,
		client_secret, // Optional for refresh_grant but required on confidential clients
		requestedScopes ?? scopes,
	);

	const user = await ctx.context.internalAdapter.findUserById(
		refreshToken.userId,
	);
	if (!user) {
		throw new APIError("BAD_REQUEST", {
			error_description: "user not found",
			error: "invalid_request",
		});
	}

	const authTime =
		refreshToken.authTime != null ? new Date(refreshToken.authTime) : undefined;

	// Generate new tokens
	return createUserTokens(
		ctx,
		opts,
		client,
		requestedScopes ?? scopes,
		user,
		refreshToken.referenceId,
		refreshToken.sessionId,
		undefined,
		{
			refreshToken,
		},
		authTime,
	);
}

/**
 * Obtain a token by exchanging another token from a trusted issuer.
 * this is useful for delegating access across different services or domains without exposing user credentials.
 *
 * Implements RFC8693 - https://datatracker.ietf.org/doc/html/rfc8693
 * @param ctx
 * @param opts
 */
export async function handleTokenExchangeGrant(
	ctx: GenericEndpointContext,
	opts: OAuthOptions<Scope[]>,
) {
	const authorization = ctx.request?.headers.get("authorization") || null;

	let {
		client_id,
		client_secret,
		subject_token,
		subject_token_type,
		scope,
		actor_token,
		actor_token_type,
		requested_token_type,
	}: {
		client_id?: string;
		client_secret?: string;
		requested_token_type?: RequestedTokenExhangeType;
		subject_token?: string;
		subject_token_type?: SubjectTokenExhangeType;
		resource?: string;
		scope?: string;
		actor_token?: string;
		actor_token_type?: ActorTokenExhangeType;
	} = ctx.body;

	const { tokenExchange } = opts;

	//convert basic authorization
	if (authorization?.startsWith("Basic ")) {
		const res = basicToClientCredentials(authorization);
		client_id = res?.client_id;
		client_secret = res?.client_secret;
	}
	if (!client_id) {
		throw new APIError("BAD_REQUEST", {
			error_description: "Missing required client_id",
			error: "invalid_grant",
		});
	}
	if (!client_secret) {
		throw new APIError("BAD_REQUEST", {
			error_description: "Missing required client_secret for token",
			error: "invalid_grant",
		});
	}

	if (!subject_token) {
		throw new APIError("BAD_REQUEST", {
			error_description: "subject_token is required",
			error: "invalid_request",
		});
	}

	if (!tokenExchange?.allowImpersonation && !actor_token) {
		throw new APIError("BAD_REQUEST", {
			error_description:
				"Impersonation mode is disabled. Provide actor_token to perform delegated token exchange.",
			error: "invalid_request",
		});
	}

	if (actor_token && !actor_token_type) {
		throw new APIError("BAD_REQUEST", {
			error_description:
				"actor_token_type is required when actor_token is provided",
			error: "invalid_request",
		});
	}

	if (
		requested_token_type &&
		!tokenExchange?.allowedRequestedTokenTypes?.includes(requested_token_type)
	) {
		throw new APIError("BAD_REQUEST", {
			error_description: "requested_token_type is not allowed",
			error: "invalid_request",
		});
	}

	//Verify client credential
	const client = await validateClientCredentials(
		ctx,
		opts,
		client_id,
		client_secret,
		scope ? scope.split(" ") : undefined,
	);

	if (
		client.grantTypes &&
		!client.grantTypes.includes(
			"urn:ietf:params:oauth:grant-type:token-exchange",
		)
	) {
		throw new APIError("BAD_REQUEST", {
			error_description: "Client not authorized to use token exchange grant",
			error: "unsupported_grant_type",
		});
	}

	//Public clients are not allowed to use this grant as it involves exchanging tokens which may have elevated privileges
	if (client.public) {
		throw new APIError("BAD_REQUEST", {
			error_description:
				"Public clients are not allowed to use token exchange grant",
			error: "unsupported_grant_type",
		});
	}

	/**
	 * TWO MODE:
	 * IMPERSONATION: Client exchanges its own token for a new token to access another resource (no actor token provided, client is the actor)
	 * DELEGATION: Client exchanges a token on behalf of a user for a new token to access another resource (actor token provided with user context)
	 */

	let actor: string | undefined;

	//Validate subject token
	const subjectTokenPayload = await validateTokenExchange({
		ctx,
		opts,
		token: subject_token,
		token_type: subject_token_type,
		token_type_allowed: tokenExchange?.allowedSubjectTokenTypes!,
	});

	if (
		(subjectTokenPayload as { active?: boolean } | undefined)?.active === false
	) {
		throw new APIError("BAD_REQUEST", {
			error_description: "subject token is not active",
			error: "invalid_token",
		});
	}

	if (!subjectTokenPayload?.sub) {
		throw new APIError("BAD_REQUEST", {
			error_description: "sub claim is not provided to determine the subject",
			error: "invalid_request",
		});
	}

	const subject = subjectTokenPayload.sub;

	let actorTokenPayload:
		| (JWTPayload & {
				azp?: string;
				client_id?: string;
		  })
		| undefined;

	//verify actor token if provided
	if (actor_token) {
		actorTokenPayload = await validateTokenExchange({
			ctx,
			opts,
			token: actor_token,
			token_type: actor_token_type,
			token_type_allowed: tokenExchange?.allowedActorTokenTypes!,
		});

		if ((actorTokenPayload as { active?: boolean })?.active === false) {
			throw new APIError("BAD_REQUEST", {
				error_description: "actor token is not active",
				error: "invalid_token",
			});
		}

		if (
			!actorTokenPayload?.sub &&
			!actorTokenPayload?.azp &&
			!actorTokenPayload?.client_id
		) {
			throw new APIError("BAD_REQUEST", {
				error_description:
					"sub, azp, or client_id claim is required on actor token to determine the actor",
				error: "invalid_request",
			});
		}

		actor =
			actorTokenPayload?.sub ??
			actorTokenPayload?.azp ??
			actorTokenPayload?.client_id;
	}

	// Validate requested scopes:
	// - Requested scopes must be a subset of the subject token's scopes
	// - The actor cannot request more scopes than the subject originally consented to
	const subTokenScopes = subjectTokenPayload?.scope?.split(" ");
	let requestedScopes = scope?.split(" ") ?? subTokenScopes;

	if (requestedScopes) {
		if (subTokenScopes) {
			const newSubTokenScopes = new Set(subTokenScopes);
			const invalidSubScopes = requestedScopes.filter(
				(scope) => !newSubTokenScopes.has(scope),
			);

			if (invalidSubScopes.length) {
				throw new APIError("BAD_REQUEST", {
					error: "invalid_scope",
					error_description: `The following scopes were not granted in the subject token: ${invalidSubScopes.join(", ")}`,
				});
			}
		} else {
			// TODO: Add proper scope validation if id_token is allowed as a subject_token.
		}
	}

	if (!requestedScopes) {
		requestedScopes = [];
	}

	// Look up the user by subject ID (may be undefined for M2M tokens)
	const subjectUser = await ctx.context.internalAdapter.findUserById(subject);

	//check audience/resource
	const audience = await checkResource(ctx, opts, requestedScopes);

	//custom claims for token exchange
	const customClaims = tokenExchange?.customAccessTokenExchangeClaims
		? await tokenExchange.customAccessTokenExchangeClaims({
				scopes: requestedScopes,
				subjectJwt: subjectTokenPayload,
				actorJwt: actorTokenPayload,
				resource: ctx.body.resource,
				metadata: parseClientMetadata(client.metadata),
			})
		: {};

	//default payload
	const newTokenPayload: JWTPayload = {
		sub: subject,
		azp: client_id,
		aud: audience ?? subjectTokenPayload?.aud,
		scope: requestedScopes.join(" "),
		...(actor_token
			? {
					act: {
						sub: actor,
					},
				}
			: {}),
	};

	const jwtPluginOptions = opts.disableJwtPlugin
		? undefined
		: getJwtPlugin(ctx.context).options;

	//token refresh generation
	async function generateRefreshTokenForExchange() {
		if (!client.grantTypes?.includes("refresh_token")) {
			throw new APIError("BAD_REQUEST", {
				error: "unauthorized_client",
				error_description: "Client not authorized to use refresh_token grant",
			});
		}

		//Refresh tokens require a user
		if (!subjectUser) {
			throw new APIError("NOT_FOUND", {
				error_description: "User not found",
				error: "invalid_request",
			});
		}

		return await createRefreshToken(
			ctx,
			opts,
			subjectUser,
			undefined,
			client,
			requestedScopes ?? [],
			{
				...newTokenPayload,
			},
		);
	}

	//Validate refresh token generation
	const isRefreshToken =
		requested_token_type === "urn:ietf:params:oauth:token-type:refresh_token" &&
		requestedScopes.includes("offline_access") &&
		!actor_token;
	const isJwtAccessToken = audience && !opts.disableJwtPlugin;
	//early refreh for opaque access token
	const earlyRefreshToken =
		isRefreshToken && !isJwtAccessToken
			? await generateRefreshTokenForExchange()
			: undefined;

	const [accessToken, refreshToken] = await Promise.all([
		audience && !opts.disableJwtPlugin
			? signJWT(ctx, {
					options: jwtPluginOptions,
					payload: {
						...customClaims,
						...newTokenPayload,
					},
				})
			: createOpaqueAccessToken(
					ctx,
					opts,
					subjectUser ?? undefined,
					client,
					requestedScopes ?? [],
					{
						...newTokenPayload,
					},
					subjectTokenPayload?.reference_id,
					earlyRefreshToken?.id,
				),
		isRefreshToken && !earlyRefreshToken
			? generateRefreshTokenForExchange()
			: undefined,
	]);

	return ctx.json(
		{
			access_token: accessToken,
			expires_in: opts.accessTokenExpiresIn ?? 3600,
			expires_at:
				Math.floor(Date.now() / 1000) + (opts.accessTokenExpiresIn ?? 3600),
			token_type: "Bearer",
			scope: newTokenPayload.scope,
			refresh_token: refreshToken?.token ?? earlyRefreshToken?.token,
		},
		{
			headers: {
				"Cache-Control": "no-store",
				Pragma: "no-cache",
			},
		},
	);
}

async function validateTokenExchange({
	ctx,
	opts,
	token,
	token_type,
	token_type_allowed,
}: {
	ctx: GenericEndpointContext;
	opts: OAuthOptions<Scope[]>;
	token: string;
	token_type?: TokenTypeIdentifier;
	token_type_allowed: TokenTypeIdentifier[];
}): Promise<
	| (JWTPayload & {
			azp?: string;
			scope?: string;
			client_id?: string;
			reference_id?: string;
	  })
	| undefined
> {
	let tokenPayload:
		| (JWTPayload & { azp?: string; scope?: string; client_id?: string })
		| undefined;

	if (token_type && !token_type_allowed?.includes(token_type)) {
		throw new APIError("BAD_REQUEST", {
			error_description: "token_type not allowed",
			error: "invalid_request",
		});
	}

	// When token_type is specified, validate against that specific type
	if (token_type === "urn:ietf:params:oauth:token-type:access_token") {
		tokenPayload = await validateAccessToken(ctx, opts, token);
		return tokenPayload;
	}
	if (token_type === "urn:ietf:params:oauth:token-type:id_token") {
		tokenPayload = await validateIdToken(ctx, opts, token);
		return tokenPayload;
	}

	// When token_type is not specified, try allowed types in order
	// Try access_token first if allowed
	if (
		token_type_allowed?.includes(
			"urn:ietf:params:oauth:token-type:access_token",
		)
	) {
		try {
			tokenPayload = await validateAccessToken(ctx, opts, token);
			// Check if validation succeeded (active token with valid claims)
			if (
				tokenPayload &&
				(tokenPayload as { active?: boolean }).active !== false
			) {
				return tokenPayload;
			}
		} catch {
			// Continue to try id_token
		}
	}

	// Try id_token if allowed and access_token failed or wasn't allowed
	if (
		token_type_allowed?.includes("urn:ietf:params:oauth:token-type:id_token")
	) {
		try {
			tokenPayload = await validateIdToken(ctx, opts, token);
			return tokenPayload;
		} catch {
			// Continue, will return undefined
		}
	}

	return tokenPayload;
}
