import type { BetterAuthClientPlugin } from "@better-auth/core";
import type { multiEmail } from ".";
import { MULTI_EMAIL_ERROR_CODES } from "./const";

export * from "./const/error-codes";

export const multiEmailClient = () => {
	return {
		id: "multi-email",
		$InferServerPlugin: {} as ReturnType<typeof multiEmail>,
		$ERROR_CODES: MULTI_EMAIL_ERROR_CODES,
	} satisfies BetterAuthClientPlugin;
};

export type MultiEmailClientPlugin = ReturnType<typeof multiEmailClient>;
