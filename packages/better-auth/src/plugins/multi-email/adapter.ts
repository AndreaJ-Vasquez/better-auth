import type { BetterAuthOptions } from "@better-auth/core";
import type { DBAdapter } from "@better-auth/core/db/adapter";
import { MODEL_MULTI_EMAIL } from "./const";
import type { MultiEmail } from "./types";

const normalizeEmail = (email: string) => email.toLowerCase();

export const multiEmailAdapter = (adapter: DBAdapter<BetterAuthOptions>) => {
	return {
		addEmail: async (
			data: Pick<MultiEmail, "email" | "userId"> &
				Partial<Pick<MultiEmail, "emailVerified" | "isPrimary" | "verifiedAt">>,
		) => {
			const emailResult = await adapter.create<
				Pick<MultiEmail, "email" | "userId"> &
					Partial<
						Pick<MultiEmail, "emailVerified" | "isPrimary" | "verifiedAt">
					>,
				MultiEmail
			>({
				model: MODEL_MULTI_EMAIL,
				data: {
					...data,
					email: normalizeEmail(data.email),
				},
			});

			return emailResult;
		},
		findEmail: async (email: string, userId?: string) => {
			const emailResult = await adapter.findOne<MultiEmail>({
				model: MODEL_MULTI_EMAIL,
				where: [
					{
						field: "email",
						value: normalizeEmail(email),
					},
					...(userId ? [{ field: "userId", value: userId }] : []),
				],
			});

			return emailResult;
		},

		findUserEmails: async (userId: string) => {
			const emailResult = await adapter.findMany<MultiEmail>({
				model: MODEL_MULTI_EMAIL,
				where: [
					{
						field: "userId",
						value: userId,
					},
				],
			});

			return emailResult;
		},
		findPrimaryEmail: async (userId: string) => {
			const emailResult = await adapter.findOne<MultiEmail>({
				model: MODEL_MULTI_EMAIL,
				where: [
					{
						field: "userId",
						value: userId,
					},
					{
						field: "isPrimary",
						value: true,
					},
				],
			});

			return emailResult;
		},
		updateEmail: async (
			emailId: string,
			data: Partial<
				Pick<MultiEmail, "isPrimary" | "emailVerified" | "verifiedAt">
			>,
		) => {
			const emailResult = await adapter.update<MultiEmail>({
				model: MODEL_MULTI_EMAIL,
				where: [
					{
						field: "id",
						value: emailId,
					},
				],
				update: data,
			});

			return emailResult;
		},
		removeEmail: async (email: string) => {
			await adapter.delete({
				model: MODEL_MULTI_EMAIL,
				where: [
					{
						field: "email",
						value: normalizeEmail(email),
					},
				],
			});
		},
	};
};
