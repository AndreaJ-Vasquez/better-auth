import type { BetterAuthPlugin } from "@better-auth/core";
import { createAuthEndpoint } from "@better-auth/core/api";
import type { User } from "@better-auth/core/db";
import { APIError } from "better-call";
import * as z from "zod";
import { createAuthMiddleware, sessionMiddleware } from "../../api";
import { multiEmailAdapter } from "./adapter";
import {
	ID_MULTI_EMAIL,
	MODEL_MULTI_EMAIL,
	MULTI_EMAIL_ERROR_CODES,
} from "./const";
import {
	addEmail,
	listEmails,
	removeEmail,
	resendVerification,
	setPrimaryEmail,
	verifyEmail,
} from "./email";
import { schema } from "./schema";
import type { MultiEmailOptions } from "./types";

export const multiEmail = (options?: MultiEmailOptions) => {
	const opts: MultiEmailOptions = {
		maxEmails: 5,
		requireVerificationOnPrimarySet: true,
		verificationTokenExpiration: 60 * 60, // 1 hour
		...options,
	};

	return {
		id: ID_MULTI_EMAIL,
		init: async (ctx) => {
			const user = await ctx.adapter.findMany<User>({ model: "user" });
			//Migrate existing emails to multi-email model
			for (const u of user) {
				const existingEmail = await ctx.adapter.findOne({
					model: MODEL_MULTI_EMAIL,
					where: [
						{ field: "userId", value: u.id },
						{ field: "isPrimary", value: true },
					],
				});

				if (!existingEmail) {
					await ctx.adapter.create({
						model: MODEL_MULTI_EMAIL,
						data: {
							userId: u.id,
							email: u.email.toLowerCase(),
							emailVerified: u.emailVerified,
							isPrimary: true,
							verifiedAt: u.emailVerified ? new Date() : undefined,
						},
					});
				}
			}
			//Hooks to sync changes
			return {
				options: {
					databaseHooks: {
						user: {
							create: {
								async before(user, ctx) {
									//Verify if email already exists in multi-email table to avoid duplicates and conflicts
									if (!ctx || !user.email) return;
									const adapter = multiEmailAdapter(ctx.context.adapter);

									const email = await adapter.findEmail(user.email);

									if (email) {
										throw new APIError("BAD_REQUEST", {
											...MULTI_EMAIL_ERROR_CODES.EMAIL_ALREADY_EXISTS,
										});
									}
								},
								async after(user, ctx) {
									//When a new user is created add their email to the multi-email table for
									// a better control over secondary emails
									if (!ctx || !user.email) return;
									const adapter = multiEmailAdapter(ctx.context.adapter);

									const email = await adapter.findEmail(user.email);

									if (!email) {
										await adapter.addEmail({
											email: user.email,
											userId: user.id,
											emailVerified: user.emailVerified,
											isPrimary: true,
											verifiedAt: user.emailVerified ? new Date() : undefined,
										});
									}
								},
							},
							update: {
								async before(user, ctx) {
									if (!ctx || !user.email) return;
									const adapter = multiEmailAdapter(ctx.context.adapter);
									const newEmail = user.email.toLowerCase();

									const emailExists = await adapter.findEmail(newEmail);

									//If the email already exists and belongs to a different user, throw an error to prevent duplicates
									if (
										emailExists &&
										emailExists.userId !==
											(user.id ?? ctx.context.session?.user?.id)
									) {
										throw new APIError("BAD_REQUEST", {
											...MULTI_EMAIL_ERROR_CODES.EMAIL_ALREADY_EXISTS,
										});
									}

									const userId = user.id ?? ctx.context.session?.user?.id!;
									const primaryEmail = await adapter.findPrimaryEmail(userId);

									if (!primaryEmail || primaryEmail.email === newEmail) return;

									const isExistingSecondary =
										emailExists && emailExists.userId === userId;

									//Avoid duplicate entries if the new email is already a secondary email
									if (isExistingSecondary) {
										await adapter.updateEmail(emailExists.id, {
											isPrimary: true,
											emailVerified:
												user.emailVerified ?? emailExists.emailVerified,
											verifiedAt:
												(user.emailVerified ?? emailExists.emailVerified)
													? (emailExists.verifiedAt ?? new Date())
													: undefined,
										});
									} else {
										await adapter.addEmail({
											email: newEmail,
											userId: userId,
											emailVerified: user.emailVerified ?? false,
											isPrimary: true,
											verifiedAt: user.emailVerified ? new Date() : undefined,
										});
									}

									await adapter.updateEmail(primaryEmail.id, {
										isPrimary: false,
									});
								},
							},
						},
					},
				},
			};
		},
		hooks: {
			before: [
				{
					matcher: (context) =>
						(context.path?.startsWith("/callback/") &&
							context.method === "GET") ??
						false,
					handler: createAuthMiddleware(async (ctx) => {
						const originalFindOAuthUser =
							ctx.context.internalAdapter.findOAuthUser;

						if (!originalFindOAuthUser) return;

						ctx.context.internalAdapter.findOAuthUser = async (
							email: string,
							accountId: string,
							providerId: string,
						) => {
							//Find the user using the original method (which checks the accounts table)
							const result = await originalFindOAuthUser(
								email,
								accountId,
								providerId,
							);

							if (result?.user) {
								return result;
							}

							// If no user was found, check if there's a verified email in the multi-email table that matches the OAuth email
							const adapter = multiEmailAdapter(ctx.context.adapter);
							const multiEmailRecord = await adapter.findEmail(
								email.toLowerCase(),
							);

							if (multiEmailRecord && multiEmailRecord.emailVerified) {
								const user = await ctx.context.adapter.findOne<User>({
									model: "user",
									where: [{ field: "id", value: multiEmailRecord.userId }],
								});

								if (user) {
									const accounts =
										await ctx.context.internalAdapter.findAccounts(user.id);

									return {
										user,
										linkedAccount: null,
										accounts,
									};
								}
							}

							return result;
						};
					}),
				},
			],
			after: [
				{
					matcher: (context) =>
						(context.path?.startsWith("/callback/") &&
							context.method === "GET") ??
						false,
					handler: createAuthMiddleware(async (ctx) => {
						// After oauth callback, ensure the user's email is added to the multi-email table
						if (ctx.context.session?.user) {
							const userId = ctx.context.session.user.id;
							const userEmail = ctx.context.session.user.email;

							const adapter = multiEmailAdapter(ctx.context.adapter);

							const existingMultiEmail = await adapter.findEmail(
								userEmail.toLowerCase(),
								userId,
							);

							if (!existingMultiEmail) {
								const primaryEmail = await adapter.findPrimaryEmail(userId);

								if (primaryEmail?.email !== userEmail.toLowerCase()) {
									await adapter.addEmail({
										email: userEmail.toLowerCase(),
										userId: userId,
										emailVerified: ctx.context.session.user.emailVerified,
										isPrimary: false,
										verifiedAt: ctx.context.session.user.emailVerified
											? new Date()
											: undefined,
									});
								}
							}
						}
					}),
				},
			],
		},
		endpoints: {
			addEmail: createAuthEndpoint(
				"/multi-email/add",
				{
					use: [sessionMiddleware],
					method: "POST",
					body: z.object({
						email: z.email().meta({
							description: "The email address to add to the account",
						}),
					}),
					metadata: {
						openapi: {
							description:
								"Add a new email address to the authenticated user's account. Sends a verification email if onEmailAdded is configured.",
							operationId: "multiEmailAdd",
							responses: {
								"200": {
									description: "Email added successfully",
									content: {
										"application/json": {
											schema: {
												type: "object",
												properties: {
													id: { type: "string" },
													userId: { type: "string" },
													email: { type: "string" },
													emailVerified: { type: "boolean" },
													isPrimary: { type: "boolean" },
													createdAt: { type: "string", format: "date-time" },
												},
												required: [
													"id",
													"userId",
													"email",
													"emailVerified",
													"isPrimary",
													"createdAt",
												],
											},
										},
									},
								},
							},
						},
					},
				},
				async (ctx) => {
					return addEmail(ctx, opts);
				},
			),
			verifyEmail: createAuthEndpoint(
				"/multi-email/verify",
				{
					method: "GET",
					query: z.object({
						token: z.string().meta({
							description: "The verification token sent to the user's email",
						}),
						callbackURL: z.string().optional().meta({
							description: "URL to redirect to after successful verification",
						}),
					}),
					metadata: {
						openapi: {
							description:
								"Verify an email address using the token sent to the user's inbox. Public endpoint (no session required).",
							operationId: "multiEmailVerify",
							responses: {
								"200": {
									description: "Email verified successfully",
									content: {
										"application/json": {
											schema: {
												type: "object",
												properties: {
													success: { type: "boolean" },
												},
												required: ["success"],
											},
										},
									},
								},
								"302": {
									description: "Redirect to callbackURL if provided",
								},
							},
						},
					},
				},
				async (ctx) => {
					return verifyEmail(ctx, opts);
				},
			),
			resendVerification: createAuthEndpoint(
				"/multi-email/resend-verification",
				{
					use: [sessionMiddleware],
					method: "POST",
					body: z.object({
						email: z.email().meta({
							description:
								"The unverified email address to resend verification for",
						}),
					}),
					metadata: {
						openapi: {
							description:
								"Resend the verification email for an unverified email address.",
							operationId: "multiEmailResendVerification",
							responses: {
								"200": {
									description: "Verification email resent successfully",
									content: {
										"application/json": {
											schema: {
												type: "object",
												properties: {
													success: { type: "boolean" },
												},
												required: ["success"],
											},
										},
									},
								},
							},
						},
					},
				},
				async (ctx) => {
					return resendVerification(ctx, opts);
				},
			),
			removeEmail: createAuthEndpoint(
				"/multi-email/remove",
				{
					use: [sessionMiddleware],
					method: "POST",
					body: z.object({
						email: z.email().meta({
							description: "The email address to remove from the account",
						}),
					}),
					metadata: {
						openapi: {
							description:
								"Remove a secondary (non-primary) email address from the user's account.",
							operationId: "multiEmailRemove",
							responses: {
								"200": {
									description: "Email removed successfully",
									content: {
										"application/json": {
											schema: {
												type: "object",
												properties: {
													success: { type: "boolean" },
												},
												required: ["success"],
											},
										},
									},
								},
							},
						},
					},
				},
				async (ctx) => {
					return removeEmail(ctx, opts);
				},
			),
			setPrimaryEmail: createAuthEndpoint(
				"/multi-email/set-primary",
				{
					use: [sessionMiddleware],
					method: "POST",
					body: z.object({
						email: z.email().meta({
							description: "The email address to set as primary",
						}),
					}),
					metadata: {
						openapi: {
							description:
								"Set a verified email as the primary email for the user's account. Syncs with the core users.email field.",
							operationId: "multiEmailSetPrimary",
							responses: {
								"200": {
									description: "Primary email updated successfully",
									content: {
										"application/json": {
											schema: {
												type: "object",
												properties: {
													success: { type: "boolean" },
												},
												required: ["success"],
											},
										},
									},
								},
							},
						},
					},
				},
				async (ctx) => {
					return setPrimaryEmail(ctx, opts);
				},
			),
			listEmails: createAuthEndpoint(
				"/multi-email/list",
				{
					use: [sessionMiddleware],
					method: "GET",
					metadata: {
						openapi: {
							description:
								"List all email addresses associated with the authenticated user's account.",
							operationId: "multiEmailList",
							responses: {
								"200": {
									description: "List of user's email addresses",
									content: {
										"application/json": {
											schema: {
												type: "array",
												items: {
													type: "object",
													properties: {
														id: { type: "string" },
														userId: { type: "string" },
														email: { type: "string" },
														emailVerified: { type: "boolean" },
														isPrimary: { type: "boolean" },
														verifiedAt: {
															type: "string",
															format: "date-time",
															nullable: true,
														},
														createdAt: { type: "string", format: "date-time" },
														updatedAt: {
															type: "string",
															format: "date-time",
															nullable: true,
														},
													},
													required: [
														"id",
														"userId",
														"email",
														"emailVerified",
														"isPrimary",
														"createdAt",
													],
												},
											},
										},
									},
								},
							},
						},
					},
				},
				async (ctx) => {
					return listEmails(ctx);
				},
			),
		},
		schema: schema,
		$ERROR_CODES: MULTI_EMAIL_ERROR_CODES,
	} satisfies BetterAuthPlugin;
};
