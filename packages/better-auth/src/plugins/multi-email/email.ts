import type { GenericEndpointContext } from "@better-auth/core";
import type { MultiEmailOptions } from "./types";
import { multiEmailAdapter } from "./adapter";
import { APIError } from "better-call";
import { MULTI_EMAIL_ERROR_CODES } from "./const";
import { generateRandomString } from "../../crypto";

async function sendVerificationEmail(
	ctx: GenericEndpointContext,
	opts: MultiEmailOptions,
	email: string,
	userId: string,
) {
	if (!opts.onEmailAdded) return;

	const token = opts.generateVerificationToken
		? await opts.generateVerificationToken({ email, userId })
		: generateRandomString(32);

	await ctx.context.internalAdapter.createVerificationValue({
		value: JSON.stringify({ email }),
		identifier: `multi-email-verify:${token}`,
		expiresAt: new Date(
			Date.now() + (opts.verificationTokenExpiration || 3600) * 1000,
		),
	});

	const url = `${ctx.context.baseURL}/multi-email/verify?token=${token}`;

	await opts.onEmailAdded({ email, userId, token, url });
}

/**
 * Add a new email to the user's account.
 */
export async function addEmail(
	ctx: GenericEndpointContext,
	opts: MultiEmailOptions,
) {
	const { email }: { email: string } = ctx.body;

	const userId = ctx.context.session?.user.id;

	const adapter = multiEmailAdapter(ctx.context.adapter, opts);

	const userEmails = await adapter.findUserEmails(userId!);
	if (userEmails.length >= (opts.maxEmails || 5)) {
		throw new APIError("BAD_REQUEST", {
			...MULTI_EMAIL_ERROR_CODES.MAX_EMAILS_REACHED,
		});
	}

	//check if email already exists
	const emailExists = await adapter.findEmail(email);

	if (emailExists) {
		throw new APIError("BAD_REQUEST", {
			...MULTI_EMAIL_ERROR_CODES.EMAIL_ALREADY_EXISTS,
		});
	}

	const newEmail = await adapter.addEmail({
		email,
		userId: userId!,
	});

	await sendVerificationEmail(ctx, opts, email, userId!);

	return newEmail;
}

/**
 * Verify a new email using the token sent to the user's email address.
 */
export async function verifyEmail(
	ctx: GenericEndpointContext,
	opts: MultiEmailOptions,
) {
	const {
		token,
		callbackURL,
	}: {
		token: string;
		callbackURL?: string;
	} = ctx.query;

	if (!token) {
		throw new APIError("BAD_REQUEST", {
			...MULTI_EMAIL_ERROR_CODES.INVALID_VERIFICATION_TOKEN,
		});
	}

	const adapter = multiEmailAdapter(ctx.context.adapter, opts);

	const verification = await ctx.context.internalAdapter.findVerificationValue(
		`multi-email-verify:${token}`,
	);

	if (!verification) {
		throw new APIError("BAD_REQUEST", {
			...MULTI_EMAIL_ERROR_CODES.INVALID_VERIFICATION_TOKEN,
		});
	}

	const { email } = JSON.parse(verification.value);

	const emailRecord = await adapter.findEmail(email);

	if (!emailRecord) {
		throw new APIError("BAD_REQUEST", {
			...MULTI_EMAIL_ERROR_CODES.EMAIL_NOT_FOUND,
		});
	}

	await adapter.updateEmail(emailRecord.id, {
		emailVerified: true,
	});

	await ctx.context.internalAdapter.deleteVerificationByIdentifier(
		`multi-email-verify:${token}`,
	);

	if (opts.onEmailVerified) {
		await opts.onEmailVerified({
			email: email.email,
			userId: email.userId,
		});
	}

	if (callbackURL) {
		throw ctx.redirect(callbackURL);
	}

	return ctx.json({ success: true });
}

/**
 *	Resend the verification email for a pending email address
 */
export async function resendVerification(
	ctx: GenericEndpointContext,
	opts: MultiEmailOptions,
) {
	const { email }: { email: string } = ctx.body;
	const userId = ctx.context.session?.user.id;

	if (!opts.onEmailAdded) {
		throw new APIError("BAD_REQUEST", {
			...MULTI_EMAIL_ERROR_CODES.MISSING_EMAIL_ADDED_HANDLER,
		});
	}

	const adapter = multiEmailAdapter(ctx.context.adapter, opts);

	const emailRecord = await adapter.findEmail(email, userId);

	if (!emailRecord) {
		throw new APIError("BAD_REQUEST", {
			...MULTI_EMAIL_ERROR_CODES.EMAIL_NOT_FOUND,
		});
	}

	if (emailRecord.emailVerified) {
		throw new APIError("BAD_REQUEST", {
			...MULTI_EMAIL_ERROR_CODES.EMAIL_ALREADY_VERIFIED,
		});
	}

	await sendVerificationEmail(ctx, opts, email, userId!);

	return ctx.json({ success: true });
}

/**
 * Remove a secondary email from the user's account.
 */
export async function removeEmail(
	ctx: GenericEndpointContext,
	opts: MultiEmailOptions,
) {
	const { email }: { email: string } = ctx.body;
	const userId = ctx.context.session?.user.id;

	const adapter = multiEmailAdapter(ctx.context.adapter, opts);

	const emailRecord = await adapter.findEmail(email, userId);

	if (!emailRecord) {
		throw new APIError("NOT_FOUND", {
			...MULTI_EMAIL_ERROR_CODES.EMAIL_NOT_FOUND,
		});
	}

	if (emailRecord.isPrimary) {
		throw new APIError("BAD_REQUEST", {
			...MULTI_EMAIL_ERROR_CODES.CANNOT_REMOVE_PRIMARY_EMAIL,
		});
	}

	const userEmails = await adapter.findUserEmails(userId!);
	if (userEmails.length <= 1) {
		throw new APIError("BAD_REQUEST", {
			...MULTI_EMAIL_ERROR_CODES.AT_LEAST_ONE_EMAIL_REQUIRED,
		});
	}

	await adapter.removeEmail(emailRecord.email);

	if (opts.onEmailRemoved) {
		await opts.onEmailRemoved({ email: emailRecord.email, userId: userId! });
	}

	return ctx.json({ success: true });
}

/**
 * Set a verified email as the primary email for the user's account.
 */
export async function setPrimaryEmail(
	ctx: GenericEndpointContext,
	opts: MultiEmailOptions,
) {
	const { email }: { email: string } = ctx.body;
	const userId = ctx.context.session?.user.id;

	const adapter = multiEmailAdapter(ctx.context.adapter, opts);

	const targetEmail = await adapter.findEmail(email, userId);

	if (!targetEmail) {
		throw new APIError("NOT_FOUND", {
			...MULTI_EMAIL_ERROR_CODES.EMAIL_NOT_FOUND,
		});
	}

	// Already primary, nothing to do
	if (targetEmail.isPrimary) {
		return ctx.json({ success: true });
	}

	if (opts.requireVerificationOnPrimarySet && !targetEmail.emailVerified) {
		throw new APIError("BAD_REQUEST", {
			...MULTI_EMAIL_ERROR_CODES.EMAIL_NOT_VERIFIED,
		});
	}

	const currentPrimary = await adapter.findPrimaryEmail(userId!);

	// Promote new primary first to avoid orphaned state
	await adapter.updateEmail(targetEmail.id, { isPrimary: true });

	if (currentPrimary) {
		await adapter.updateEmail(currentPrimary.id, { isPrimary: false });
	}

	// Sync with users.email in core
	await ctx.context.internalAdapter.updateUser(userId!, {
		email: targetEmail.email,
		emailVerified: targetEmail.emailVerified,
	});

	if (opts.onPrimaryEmailChanged) {
		await opts.onPrimaryEmailChanged({
			oldEmail: currentPrimary?.email || null,
			newEmail: targetEmail.email,
			userId: userId!,
		});
	}

	return ctx.json({ success: true });
}

/**
 * List all emails associated with the user's account.
 */
export async function listEmails(
	ctx: GenericEndpointContext,
	opts: MultiEmailOptions,
) {
	const userId = ctx.context.session?.user.id;

	const adapter = multiEmailAdapter(ctx.context.adapter, opts);

	const emails = await adapter.findUserEmails(userId!);

	return ctx.json(emails);
}
