package dasniko.keycloak.authenticator;

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

import static dasniko.keycloak.authenticator.OTPConstants.*;

/**
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 */
@AutoService(AuthenticatorFactory.class)
public class EmailAuthenticatorFactory implements AuthenticatorFactory {

	public static final String PROVIDER_ID = "email-authenticator";

	private static final EmailAuthenticator SINGLETON = new EmailAuthenticator();

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public String getDisplayType() {
		return "Email OTP Authentication";
	}

	@Override
	public String getHelpText() {
		return "Validates an OTP sent via email to the user.";
	}

	@Override
	public String getReferenceCategory() {
		return "otp";
	}

	@Override
	public boolean isConfigurable() {
		return true;
	}

	@Override
	public boolean isUserSetupAllowed() {
		return true;
	}

	@Override
	public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
		return REQUIREMENT_CHOICES;
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return List.of(
			new ProviderConfigProperty(CODE_LENGTH, "Code length", "The number of digits of the generated code.", ProviderConfigProperty.STRING_TYPE, 6),
			new ProviderConfigProperty(CODE_TTL, "Time-to-live", "The time to live in seconds for the code to be valid.", ProviderConfigProperty.STRING_TYPE, "300"),
			new ProviderConfigProperty(SENDER_ID, "SenderId", "The sender ID is displayed as the message sender on the receiving device.", ProviderConfigProperty.STRING_TYPE, "Keycloak"),
			new ProviderConfigProperty(SIMULATION_MODE, "Simulation mode", "In simulation mode, the email won't be sent, but printed to the server logs", ProviderConfigProperty.BOOLEAN_TYPE, true)
		);
	}

	@Override
	public Authenticator create(KeycloakSession session) {
		return SINGLETON;
	}

	@Override
	public void init(Config.Scope config) {
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
	}

	@Override
	public void close() {
	}

}
