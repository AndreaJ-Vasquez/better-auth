import { defineErrorCodes } from "@better-auth/core/utils/error-codes";

export const MULTI_EMAIL_ERROR_CODES = defineErrorCodes({
	EMAIL_ALREADY_EXISTS: "This email is already registered",
	EMAIL_ALREADY_LINKED_TO_ACCOUNT:
		"This email is already linked to your account",
	INVALID_VERIFICATION_TOKEN:
		"The verification token is invalid or has expired",
	MAX_EMAILS_REACHED: "You have reached the maximum number of linked emails",
	CANNOT_REMOVE_PRIMARY_EMAIL: "You cannot remove your primary email address",
	EMAIL_NOT_FOUND: "The specified email was not found",
	EMAIL_NOT_VERIFIED: "Email must be verified before setting as primary",
	EMAIL_DOES_NOT_BELONG_TO_USER: "This email does not belong to your account",
	VERIFICATION_EMAIL_ALREADY_SENT:
		"A verification email was recently sent to this address",
	AT_LEAST_ONE_EMAIL_REQUIRED: "You must have at least one email address",
	INVALID_EMAIL_FORMAT: "Invalid email format",
	MISSING_EMAIL_ADDED_HANDLER:
		"The onEmailAdded handler must be defined to resend verification emails",
	EMAIL_ALREADY_VERIFIED: "This email is already verified",
});
