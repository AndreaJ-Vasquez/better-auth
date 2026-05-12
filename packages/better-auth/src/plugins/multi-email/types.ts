/**
 * Multi-email plugin options and types.
 * This plugin allows users to have multiple email addresses associated with their account,
 * each with independent verification and primary status.
 */
export type MultiEmailOptions = {
	/**
	 * Maximum number of emails a user can have. Default is 5.
	 * @default 5
	 */
	maxEmails?: number;
	/**
	 * Whether to require email verification before allowing an email to be set as primary.
	 * @default true
	 */
	requireVerificationOnPrimarySet?: boolean;
	/**
	 * Time in seconds until the verification token expires.
	 * @default 3600
	 */
	verificationTokenExpiration?: number;
	/**
	 * Allow unverified emails to be used for sign-in.
	 * @default false
	 */
	allowUnverifiedSignIn?: boolean;
	/**
	 * Custom function to generate verification token.
	 */
	generateVerificationToken?: (data: {
		email: string;
		userId: string;
	}) => string | Promise<string>;
	/**
	 * Called after an email is added. Use this to send a verification email.
	 */
	onEmailAdded?: (data: {
		email: string;
		userId: string;
		token: string;
		url: string;
	}) => void | Promise<void>;
	/**
	 * Called after an email is removed. Use this to notify the user.
	 */
	onEmailRemoved?: (data: {
		email: string;
		userId: string;
	}) => void | Promise<void>;
	/**
	 * Called after an email is verified. Use this to notify the user.
	 */
	onEmailVerified?: (data: {
		email: string;
		userId: string;
	}) => void | Promise<void>;
	/**
	 * Called after the primary email is changed. Use this to notify the user.
	 */
	onPrimaryEmailChanged?: (data: {
		oldEmail: string | null;
		newEmail: string;
		userId: string;
	}) => void | Promise<void>;
};

/**
 * Database model for a user's email address.
 */
export interface MultiEmail {
	id: string;
	userId: string;
	email: string;
	emailVerified: boolean;
	isPrimary: boolean;
	verifiedAt?: Date;
	createdAt: Date;
	updatedAt?: Date;
}
