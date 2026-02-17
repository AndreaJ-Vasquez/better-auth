import type {BetterAuthPlugin} from "@better-auth/core";
import {ID_MULTI_EMAIL, 
    MULTI_EMAIL_ERROR_CODES,
    MODEL_MULTI_EMAIL
} from "./const";
import { createAuthEndpoint } from "@better-auth/core/api";
import { APIError } from "better-call";
import {schema} from "./schema"
import type {MultiEmailOptions} from "./types";
import {z} from "zod";
import {addEmail} from "./email"
import type { User } from "@better-auth/core/db";
import { multiEmailAdapter } from "./adapter";

export const multiEmail = (
    options?: MultiEmailOptions
) => {

    const opts: MultiEmailOptions = {
        allowUnverifiedSignIn: false,
        maxEmails: 5,
        requireVerificationOnPrimarySet: true,
        verificationTokenExpiration: 60 * 60, // 1 hour
        ...options
    }

    return {
        id: ID_MULTI_EMAIL,
        init: async (ctx) => {
            const user = await ctx.adapter.findMany<User>({model: "user"})
            //Migrate existing emails to multi-email model
            for(const u of user){
                const existingEmail = await ctx.adapter.findOne({
                    model: MODEL_MULTI_EMAIL,
                    where: [
                        { field: "userId", value: u.id},
                        {field: "isPrimary", value: true}
                    ]
                })

                if(!existingEmail){
                    await ctx.adapter.create({
                        model: MODEL_MULTI_EMAIL,
                        data: {
                            userId: u.id,
                            email: u.email,
                            emailVerified: u.emailVerified,
                            isPrimary: true,
                            verifiedAt: u.emailVerified ? new Date() : undefined
                        }
                    })
                }
            }
            //Hooks to sync changes
            return {
                options: {
                    databaseHooks: {
                        user: {
                            create: {
                                 async before(user, ctx){
                                    //Verify if email already exists in multi-email table to avoid duplicates and conflicts
                                    if(!ctx) return;
                                    const adapter =  multiEmailAdapter(
                                        ctx.context.adapter,
                                        opts
                                    )

                                        const email = await adapter.findEmail(user.email)
                                        
                                        if(!email){
                                            throw new APIError(
                                            "BAD_REQUEST",
                                            {
                                                ...MULTI_EMAIL_ERROR_CODES.EMAIL_ALREADY_EXISTS
                                            }
                                            )
                                        }
                                 },
                                  async after(user, ctx) {
                                    //When a new user is created add their email to the multi-email table for 
                                    // a better control over secondary emails
                                      if(!ctx) return;
                                        const adapter =  multiEmailAdapter(
                                            ctx.context.adapter,
                                            opts
                                        )

                                        const email = await adapter.findEmail(user.email)
                                        
                                        if(!email){
                                            await adapter.addEmail({
                                                email: user.email,
                                                userId: user.id
                                            })
                                        }
                                  },
                            },
                            update: {
                                async before(user, ctx){
                                    //If email change is attempted through the user endpoint, verify if the new email already exists in the multi-email table to avoid duplicates and conflicts
                                    if(!ctx || !user.email) return;
                                    const adapter =  multiEmailAdapter(
                                        ctx.context.adapter,
                                        opts
                                    )

                                    const email = await adapter.findEmail(user.email)
                                    
                                    if(email){
                                        throw new APIError(
                                        "BAD_REQUEST",
                                        {
                                            ...MULTI_EMAIL_ERROR_CODES.EMAIL_ALREADY_EXISTS
                                        }
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        endpoints: {
            addEmail: createAuthEndpoint(
                `${ID_MULTI_EMAIL}/add`,
                {
                    method: "POST",
                    body: z.object({
                        email: z.email(),
                    })
                },
                async (ctx) => {
                   await addEmail(ctx, opts)
                }
            ),
            verifyEmail: createAuthEndpoint(
                "/multi-email/verify",
                {
                    method: "POST",
                },
                async (ctx) => {
                    throw new APIError(
                        "NOT_IMPLEMENTED"
                    )
                }
            ),
            sendVerification: createAuthEndpoint(
                "/multi-email/send-verification",
                {
                    method: "POST",
                },
                async (ctx) => {
                    throw new APIError(
                        "NOT_IMPLEMENTED"
                    )
                }
            ),
            removeEmail: createAuthEndpoint(
                "/multi-email/remove",
                {
                    method: "POST",
                },
                async (ctx) => {
                    throw new APIError(
                        "NOT_IMPLEMENTED"
                    )
                }
            ),
            setPrimaryEmail: createAuthEndpoint(
                "/multi-email/set-primary",
                {
                    method: "POST",
                },
                async (ctx) => {
                    throw new APIError(
                        "NOT_IMPLEMENTED"
                    )
                }
            ),
            listEmails: createAuthEndpoint(
                "/multi-email/list",
                {
                    method: "GET",
                },
                async (ctx) => {
                    throw new APIError(
                        "NOT_IMPLEMENTED"
                    )
                }
            ),
            resendVerification: createAuthEndpoint(
                "/multi-email/resend-verification",
                {
                    method: "POST",
                },
                async (ctx) => {
                    throw new APIError(
                        "NOT_IMPLEMENTED"
                    )
                }
            ),
        },
        schema: schema,
        $ERROR_CODES: MULTI_EMAIL_ERROR_CODES
    } satisfies BetterAuthPlugin;
} 