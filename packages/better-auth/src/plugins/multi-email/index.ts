import type { BetterAuthPlugin } from "@better-auth/core";
import {
	ID_MULTI_EMAIL,
	MULTI_EMAIL_ERROR_CODES,
	MODEL_MULTI_EMAIL,
} from "./const";
import { createAuthEndpoint } from "@better-auth/core/api";
import { APIError } from "better-call";
import { schema } from "./schema";
import type { MultiEmailOptions } from "./types";
import * as z from "zod";
import {
	addEmail,
	listEmails,
	removeEmail,
	resendVerification,
	setPrimaryEmail,
	verifyEmail,
} from "./email";
import type { User } from "@better-auth/core/db";
import { multiEmailAdapter } from "./adapter";
import { sessionMiddleware } from "../../api";

export const multiEmail = (options?: MultiEmailOptions) => {
	const opts: MultiEmailOptions = {
		allowUnverifiedSignIn: false,
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
							email: u.email,
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
									if (!ctx) return;
									const adapter = multiEmailAdapter(ctx.context.adapter, opts);

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
									if (!ctx) return;
									const adapter = multiEmailAdapter(ctx.context.adapter, opts);

									const email = await adapter.findEmail(user.email);

									if (!email) {
										await adapter.addEmail({
											email: user.email,
											userId: user.id,
										});
									}
								},
							},
							update: {
								async before(user, ctx) {
									if (!ctx || !user.email) return;
									const adapter = multiEmailAdapter(ctx.context.adapter, opts);
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
										});
									} else {
										await adapter.addEmail({
											email: newEmail,
											userId: userId,
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
		endpoints: {
			addEmail: createAuthEndpoint(
				`${ID_MULTI_EMAIL}/add`,
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
					await addEmail(ctx, opts);
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
					await verifyEmail(ctx, opts);
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
					await resendVerification(ctx, opts);
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
					await removeEmail(ctx, opts);
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
					await setPrimaryEmail(ctx, opts);
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
					return listEmails(ctx, opts);
				},
			),
		},
		schema: schema,
		$ERROR_CODES: MULTI_EMAIL_ERROR_CODES,
	} satisfies BetterAuthPlugin;
};
