import type {DBAdapter} from "@better-auth/core/db/adapter";
import type { BetterAuthOptions} from "@better-auth/core"
import type { MultiEmailOptions, MultiEmail } from "./types";
import {MODEL_MULTI_EMAIL} from "./const"

export const multiEmailAdapter = (
    adapter: DBAdapter<BetterAuthOptions>,
    options?: MultiEmailOptions
) => {
    return {
        addEmail: async ({
            email,
            userId
        }: {
            email: string,
            userId: string
        }) => {
                const emailResult = await adapter.create<
                Pick<MultiEmail, "email" | "userId">, MultiEmail>({
                    model: MODEL_MULTI_EMAIL,
                    data: {
                        email,
                        userId
                    }
                })

                return emailResult;
        },
        findEmail: async (email: string) => {
            const emailResult = await adapter.findOne<MultiEmail>({
                model: MODEL_MULTI_EMAIL,
                where: [
                    {
                        field: "email",
                        value: email.toLowerCase()
                    }
                ]
            })

            return emailResult;
        },

        findUserEmails: async (userId: string)=> {
            const emailResult = await adapter.findMany<MultiEmail>({
                model: MODEL_MULTI_EMAIL,
                where: [
                    {
                        field: "userId",
                        value: userId
                    }
                ]
            })

            return emailResult;
        }
    }
}