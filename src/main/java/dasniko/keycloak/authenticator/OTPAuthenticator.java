package dasniko.keycloak.authenticator;

import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;

import static dasniko.keycloak.authenticator.OTPConstants.*;

public abstract class OTPAuthenticator implements Authenticator {

	protected String getSecretCode(AuthenticatorConfigModel config) {
		int length = Integer.parseInt(config.getConfig().get(CODE_LENGTH));
        return SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
	}

	protected Integer getTTL(AuthenticatorConfigModel config) {
		return Integer.parseInt(config.getConfig().get(CODE_TTL));
	}

	/**
	 * Validates that auth session context has required defined values
	 * Will throw an error if code or ttl values are not defined
	 * An error page will be displayed in the UI
	 * @param  context  AuthenticationFlowContext
	 * @return void
	 */
	protected void codeContextIsValid(AuthenticationFlowContext context) {
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String code = authSession.getAuthNote(CODE);
		String ttl = authSession.getAuthNote(CODE_TTL);
		if (code == null || ttl == null) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

	/**
	 * Checks that the OTP code entered by a user matches the code in the auth session context
	 * @param  context  AuthenticationFlowContext
	 * @return boolean
	 */
	private boolean enteredCodeIsValid(AuthenticationFlowContext context) {
		String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst(CODE);
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String code = authSession.getAuthNote(CODE);
		return enteredCode.equals(code);
	}

	/**
	 * Validates that the OTP code entered by a user is correct, and still valid for use in the current session.
	 * On success, OTP flow is complete.
	 * If either check fails, will throw an error.
	 * An error screen will be displayed in the UI indicating the type of error.
	 * @param  context  AuthenticationFlowContext
	 * @param formCode String
	 * @return void
	 */
	protected void validateEnteredCode(AuthenticationFlowContext context, String formCode) {
		// TODO: can/should we add a maximum number of attempts before cancelling the session/throwing an error?
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String ttl = authSession.getAuthNote(CODE_TTL);
		boolean isValid = enteredCodeIsValid(context);
		if (isValid) {
			// ttl is still valid
			if (Long.parseLong(ttl) < System.currentTimeMillis()) {
				// expired
				context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
					context.form().setError("authCodeExpired").createErrorPage(Response.Status.BAD_REQUEST));
			} else {
				// valid
				context.success();
			}
		} else {
			// invalid
			AuthenticationExecutionModel execution = context.getExecution();
			if (execution.isRequired()) {
				context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
					context.form().setAttribute("realm", context.getRealm())
						.setError("authCodeInvalid").createForm(formCode));
			} else if (execution.isConditional() || execution.isAlternative()) {
				context.attempted();
			}
		}
	}
	@Override
	public boolean requiresUser() {
		return true;
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
		// this will only work if you have the required action from here configured:
		// https://github.com/dasniko/keycloak-extensions-demo/tree/main/requiredaction
		//	this required action example enforces the user to update their mobile phone number, if not already set.
		//	since we ask for this info on registration, or we use email which must be defined, it is not necessary
		//	user.addRequiredAction("mobile-number-ra");
	}

	@Override
	public void close() {
	}
}
