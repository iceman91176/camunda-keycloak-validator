package de.witcom.camunda.jwt

import io.digitalstate.camunda.authentication.jwt.AbstractValidatorJwt
import io.digitalstate.camunda.authentication.jwt.ValidatorResultJwt

import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.RSAPublicKeySpec
import java.util.Base64.Decoder
import java.util.Set

import org.keycloak.RSATokenVerifier
import org.keycloak.common.VerificationException
import org.keycloak.jose.jws.JWSHeader
import org.keycloak.representations.AccessToken
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import com.fasterxml.jackson.databind.ObjectMapper

import groovy.transform.CompileStatic

@CompileStatic
class KeycloakValidator extends AbstractValidatorJwt{
	
	private static final Logger LOG = LoggerFactory.getLogger(KeycloakValidator.class)
	private String serverUrl = null
	private String realmId = null
	private String clientId = null
	private String groupPrefix = "camunda_group-";
	private String tenantPrefix = "camunda_tenant-";

	@Override
	public ValidatorResultJwt validateJwt(String encodedCredentials, String jwtSecretPath) {
		
		if (!serverUrl) {
			serverUrl = System.getenv("KEYCLOAK_SERVER_URL")
			if (!serverUrl) {
				LOG.error("Keycloak Server URL not set - authorisation not possible")
				return ValidatorResultJwt.setValidatorResult(false, null, null, null)
			}
		}
		
		if (!realmId) {
			realmId = System.getenv("KEYCLOAK_REALM_ID")
			if (!realmId) {
				LOG.error("Keycloak REALM-ID not set - authorisation not possible")
				return ValidatorResultJwt.setValidatorResult(false, null, null, null)
			}
		}
		
		if (!clientId) {
			clientId = System.getenv("KEYCLOAK_CLIENT_ID")
			if (!clientId) {
				LOG.error("Keycloak KEYCLOAK_CLIENT_ID not set - authorisation not possible")
				return ValidatorResultJwt.setValidatorResult(false, null, null, null)
			}
		}
		
		if (System.getenv("ROLE_PREFIX_GROUP")){
		    groupPrefix = System.getenv("ROLE_PREFIX_GROUP")
		}
		
	    if (System.getenv("ROLE_PREFIX_TENANT")){
		    tenantPrefix = System.getenv("ROLE_PREFIX_TENANT")
		}
		
		
		AccessToken accessToken = extractAccessToken(encodedCredentials);
		if (accessToken == null) {
			return ValidatorResultJwt.setValidatorResult(false, null, null, null)
		}
		String username = accessToken.getPreferredUsername();
		
		
		ArrayList<String> groupIds = new ArrayList<String>();
		ArrayList<String> tenantIds = new ArrayList<String>();

		//Get Groups & Tenants from Keycloak-roles
		//to distinguish them, role-groups are prefixed by Variable groupPrefix, role-tennats by variable tenantPrefix
		Map<String,AccessToken.Access> resAccess = accessToken.getResourceAccess();
		if (resAccess.containsKey(clientId)){
		    Set<String> roles = resAccess.get(clientId).getRoles();
		    LOG.debug("Found resource-roles in token {}",roles.toString())
		    roles.each {
		        if (it.startsWith(groupPrefix)){
		          groupIds.add(it.substring(groupPrefix.length()))
		        }
		        if (it.startsWith(tenantPrefix)){
		          tenantIds.add(it.substring(tenantPrefix.length()))
		        }
		    }
		}else {
		    LOG.error("No resource roles found")
		}
		
		LOG.debug("Extracted camunda-groups {} from token",groupIds.toString())

        //Alternative to keycloak roles - groups and tenants are passed as claim
		Map<String, Object> claims = accessToken.getOtherClaims();
		if (claims.containsKey("groupIds")) {
			groupIds = (ArrayList<String>) claims.get("groupIds");
		}
		
		if (claims.containsKey("tenantIds")) {
			tenantIds = (ArrayList<String>) claims.get("tenantIds");
		}
		
		if (!username){
			LOG.error("BAD JWT: Missing username")
			return ValidatorResultJwt.setValidatorResult(false, null, null, null)
		}

		return ValidatorResultJwt.setValidatorResult(true, username, groupIds, tenantIds)
	}
	
	public AccessToken extractAccessToken(String token) {
		
		if (token == null) {
			LOG.error("ERROR: Access-token is null")
			return null;
		}
		
		try {
			RSATokenVerifier verifier = RSATokenVerifier.create(token)
			PublicKey publicKey = retrievePublicKeyFromCertsEndpoint( verifier.getHeader())
			
			return verifier.realmUrl(getRealmUrl()) //
			  .publicKey(publicKey) //
			  .verify() //
			  .getToken();
		  } catch (VerificationException e) {
			  LOG.error("ERROR: Unable to load JWT Secret: ${e.getLocalizedMessage()}")
			  return null;
		  }
		
	}
	
	private PublicKey retrievePublicKeyFromCertsEndpoint(JWSHeader jwsHeader) {
		try {
		  ObjectMapper om = new ObjectMapper();
		  @SuppressWarnings("unchecked")
		  Map<String, Object> certInfos = om.readValue(new URL(getRealmCertsUrl()).openStream(), Map.class);

		  List<Map<String, Object>> keys = (List<Map<String, Object>>) certInfos.get("keys");

		  Map<String, Object> keyInfo = null;
		  for (Map<String, Object> key : keys) {
			String kid = (String) key.get("kid");

			if (jwsHeader.getKeyId().equals(kid)) {
			  keyInfo = key;
			  break;
			}
		  }

		  if (keyInfo == null) {
			return null;
		  }

		  KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		  String modulusBase64 = (String) keyInfo.get("n");
		  String exponentBase64 = (String) keyInfo.get("e");

		  // see org.keycloak.jose.jwk.JWKBuilder#rs256
		  Decoder urlDecoder = Base64.getUrlDecoder();
		  BigInteger modulus = new BigInteger(1, urlDecoder.decode(modulusBase64));
		  BigInteger publicExponent = new BigInteger(1, urlDecoder.decode(exponentBase64));

		  return keyFactory.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));

		} catch (Exception e) {
			LOG.error("Unable to get public key from certendpoints " + e.getMessage());
		}
		return null;
	  }

	  public String getRealmUrl() {
		  return serverUrl + "/realms/" + realmId
		}

		public String getRealmCertsUrl() {
		  return getRealmUrl() + "/protocol/openid-connect/certs"
		}


}
