import type { BetterAuthPluginDBSchema } from "@better-auth/core/db";
import { MODEL_MULTI_EMAIL } from "../const";

export const schema = {
	/**
	 * Email model to support multiple emails per user.
	 * Each email can be verified independently and marked as primary.
	 */
	multiEmail: {
		modelName: MODEL_MULTI_EMAIL,
		fields: {
			id: {
				type: "string",
				required: true,
			},
			userId: {
				type: "string",
				required: true,
				references: {
					model: "user",
					field: "id",
					onDelete: "cascade",
				},
				index: true,
			},
			email: {
				type: "string",
				required: true,
				unique: true,
				sortable: true,
				index: true,
			},
			emailVerified: {
				type: "boolean",
				required: true,
				defaultValue: false,
			},
			isPrimary: {
				type: "boolean",
				required: true,
				defaultValue: false,
				index: true,
			},
			verifiedAt: {
				type: "date",
				required: false,
			},
			createdAt: {
				type: "date",
				required: true,
				defaultValue: () => new Date(),
			},
			updatedAt: {
				type: "date",
				required: false,
				onUpdate: () => new Date(),
			},
		},
	},
} satisfies BetterAuthPluginDBSchema;
