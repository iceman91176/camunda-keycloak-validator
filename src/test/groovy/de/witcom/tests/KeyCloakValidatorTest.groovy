package de.witcom.tests

import static org.junit.Assert.*

import io.digitalstate.camunda.authentication.jwt.AbstractValidatorJwt
import io.digitalstate.camunda.authentication.jwt.ValidatorResultJwt
import org.junit.Ignore
import org.junit.Test

class KeyCloakValidatorTest {

	@Test
	@Ignore
	public void testValidateJwtStringString() {
		
		ValidatorResultJwt validatorResult
		Class<?> jwtValidatorClass
		
		try{
			jwtValidatorClass = getClass().getClassLoader().loadClass('de.witcom.camunda.jwt.KeycloakValidator')
		} catch(all){
			// @TODO Add better Exception handling for JWT Validator class loading
			fail("Could not load Jwt Validator Class" + all.getLocalizedMessage())
		}
		try{
			AbstractValidatorJwt validator = (AbstractValidatorJwt)jwtValidatorClass.newInstance()
			validatorResult = validator.validateJwt('TOKEN', null)
		} catch(all){
			fail("Could not load Jwt Validator Class" + all.getLocalizedMessage())
		}
	}

}
