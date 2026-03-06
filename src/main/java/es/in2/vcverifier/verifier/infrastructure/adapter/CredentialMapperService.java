package es.in2.vcverifier.verifier.infrastructure.adapter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import es.in2.vcverifier.verifier.domain.exception.CredentialMappingException;
import es.in2.vcverifier.verifier.domain.exception.InvalidCredentialTypeException;
import es.in2.vcverifier.verifier.domain.model.credentials.lear.LEARCredential;
import es.in2.vcverifier.verifier.domain.model.credentials.lear.employee.LEARCredentialEmployeeV1;
import es.in2.vcverifier.verifier.domain.model.credentials.lear.employee.LEARCredentialEmployeeV2;
import es.in2.vcverifier.verifier.domain.model.credentials.lear.employee.LEARCredentialEmployeeV3;
import es.in2.vcverifier.verifier.domain.model.credentials.lear.machine.LEARCredentialMachineV1;
import es.in2.vcverifier.verifier.domain.model.credentials.lear.machine.LEARCredentialMachineV2;
import es.in2.vcverifier.verifier.domain.model.enums.LEARCredentialType;
import es.in2.vcverifier.shared.crypto.JWTService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static es.in2.vcverifier.shared.domain.util.Constants.*;

/**
 * Maps a JWT VC payload to a typed {@link LEARCredential} based on credential type and context version.
 */
@Service
@RequiredArgsConstructor
public class CredentialMapperService {

    private final JWTService jwtService;
    private final ObjectMapper objectMapper;

    public LEARCredential mapPayloadToVerifiableCredential(Payload payload) {
        Object vcObject = jwtService.extractVCFromPayload(payload);
        try {
            Map<String, Object> vcMap = validateAndCastToMap(vcObject);
            List<String> types = extractAndValidateTypes(vcMap);
            return mapToSpecificCredential(vcMap, types);
        } catch (IllegalArgumentException e) {
            throw new CredentialMappingException("Error mapping VC payload to specific Verifiable Credential class: " + e.getMessage());
        }
    }

    private Map<String, Object> validateAndCastToMap(Object vcObject) {
        if (!(vcObject instanceof Map<?, ?> map)) {
            throw new CredentialMappingException("Invalid payload format for Verifiable Credential.");
        }

        Map<String, Object> validatedMap = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!(entry.getKey() instanceof String)) {
                throw new CredentialMappingException("Invalid key type found in Verifiable Credential map: " + entry.getKey());
            }
            validatedMap.put((String) entry.getKey(), entry.getValue());
        }

        return validatedMap;
    }

    private List<String> extractAndValidateTypes(Map<String, Object> vcMap) {
        Object typeObject = vcMap.get("type");

        if (!(typeObject instanceof List<?> typeList)) {
            throw new CredentialMappingException("'type' key is not a list.");
        }

        if (!typeList.stream().allMatch(String.class::isInstance)) {
            throw new CredentialMappingException("'type' list contains non-string elements.");
        }

        return typeList.stream()
                .map(String.class::cast)
                .toList();
    }

    private List<String> extractContext(Map<String, Object> vcMap) {
        Object contextObj = vcMap.get("@context");
        if (!(contextObj instanceof List<?> contextList)) {
            throw new CredentialMappingException("The field '@context' is not a list.");
        }
        if (!contextList.stream().allMatch(String.class::isInstance)) {
            throw new CredentialMappingException("The field '@context' contains non-string elements.");
        }
        return contextList.stream().map(String.class::cast).toList();
    }

    private LEARCredential mapToSpecificCredential(Map<String, Object> vcMap, List<String> types) {
        List<String> contextList = extractContext(vcMap);

        if (types.contains(LEARCredentialType.LEAR_CREDENTIAL_EMPLOYEE.getValue())) {
            if (contextList.equals(LEAR_CREDENTIAL_EMPLOYEE_V1_CONTEXT)) {
                return objectMapper.convertValue(vcMap, LEARCredentialEmployeeV1.class);
            } else if (contextList.equals(LEAR_CREDENTIAL_EMPLOYEE_V2_CONTEXT)) {
                return objectMapper.convertValue(vcMap, LEARCredentialEmployeeV2.class);
            } else if (contextList.equals(LEAR_CREDENTIAL_EMPLOYEE_V3_CONTEXT)) {
                return objectMapper.convertValue(vcMap, LEARCredentialEmployeeV3.class);
            } else {
                throw new InvalidCredentialTypeException("Unknown LEARCredentialEmployee version: " + contextList);
            }
        } else if (types.contains(LEARCredentialType.LEAR_CREDENTIAL_MACHINE.getValue())) {
            if (contextList.equals(LEAR_CREDENTIAL_MACHINE_V2_CONTEXT)) {
                return objectMapper.convertValue(vcMap, LEARCredentialMachineV2.class);
            } else {
                return objectMapper.convertValue(vcMap, LEARCredentialMachineV1.class);
            }
        } else {
            throw new InvalidCredentialTypeException("Unsupported credential type: " + types);
        }
    }
}
