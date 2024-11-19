package dasniko.keycloak.authenticator.gateway;

/**
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 */
public interface SmsService {

	void send(String phoneNumber, String message);

}
