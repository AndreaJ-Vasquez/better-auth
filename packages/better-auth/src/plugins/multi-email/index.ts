import type {BetterAuthPlugin} from "@better-auth/core";
import {ID_MULTI_EMAIL} from "./const";
import { createAuthEndpoint } from "@better-auth/core/api";
import { APIError } from "better-call";

export const multiEmail = () => {

    return {
        id: ID_MULTI_EMAIL,
        endpoints: {
            addEmail: createAuthEndpoint(
                "/multi-email/add",
                {
                    method: "POST",
                },
                async (ctx) => {
                    throw new APIError(
                        "NOT_IMPLEMENTED"
                    )
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
        }
    } satisfies BetterAuthPlugin;
} 