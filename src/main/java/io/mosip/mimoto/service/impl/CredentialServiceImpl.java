package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.itextpdf.html2pdf.ConverterProperties;
import com.itextpdf.html2pdf.HtmlConverter;
import com.itextpdf.html2pdf.resolver.font.DefaultFontProvider;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.IdpException;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.exception.VCVerificationException;
import io.mosip.mimoto.model.QRCodeType;
import io.mosip.mimoto.service.CredentialService;
import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.util.JoseUtil;
import io.mosip.mimoto.util.RestApiClient;
import io.mosip.mimoto.util.Utilities;
import io.mosip.pixelpass.PixelPass;
import io.mosip.vercred.vcverifier.CredentialsVerifier;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;
import io.mosip.vercred.vcverifier.data.VerificationResult;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.jetbrains.annotations.NotNull;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.MediaType;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static io.mosip.mimoto.exception.ErrorConstants.*;

@Slf4j
@Service
public class CredentialServiceImpl implements CredentialService {

    @Autowired
    private Utilities utilities;

    @Autowired
    private JoseUtil joseUtil;

    @Autowired
    private RestApiClient restApiClient;

    @Autowired
    IssuersService issuerService;

    @Autowired
    DataShareServiceImpl dataShareService;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    IdpService idpService;

    @Autowired
    RestTemplate restTemplate;

    @Value("${mosip.inji.ovp.qrdata.pattern}")
    String ovpQRDataPattern;

    @Value("${mosip.inji.qr.code.height:500}")
    Integer qrCodeHeight;

    @Value("${mosip.inji.qr.code.width:500}")
    Integer qrCodeWidth;

    @Value("${mosip.inji.qr.data.size.limit:2000}")
    Integer allowedQRDataSizeLimit;

    @Autowired
    PresentationServiceImpl presentationService;

    PixelPass pixelPass;
    CredentialsVerifier credentialsVerifier;
    @PostConstruct
    public void init(){
        pixelPass = new PixelPass();
        credentialsVerifier = new CredentialsVerifier();
    }

    @Override
    public TokenResponseDTO getTokenResponse(Map<String, String> params, String issuerId) throws ApiNotAccessibleException, IOException {
        IssuerDTO issuerDTO = issuerService.getIssuerConfig(issuerId);
        HttpEntity<MultiValueMap<String, String>> request = idpService.constructGetTokenRequest(params, issuerDTO);
        TokenResponseDTO response = restTemplate.postForObject(idpService.getTokenEndpoint(issuerDTO), request, TokenResponseDTO.class);
        if(response == null) {
            throw new IdpException("Exception occurred while performing the authorization");
        }
        return response;
    }

    // @Override
    // public TokenResponseDTO getSingpassTokenResponse(Map<String, String> params, String issuerId) throws ApiNotAccessibleException, IOException {
    //     IssuerDTO issuerDTO = issuerService.getIssuerConfig(issuerId);
    //     HttpEntity<MultiValueMap<String, String>> request = idpService.constructGetTokenRequest(params, issuerDTO);
    //     TokenResponseDTO response = restTemplate.postForObject(idpService.getTokenEndpoint(issuerDTO), request, TokenResponseDTO.class);
    //     if(response == null) {
    //         throw new IdpException("Exception occurred while performing the authorization");
    //     }
    //     return response;
    // }
    


    @Override
    public ByteArrayInputStream downloadCredentialAsPDF(String issuerId, String credentialType, TokenResponseDTO response, String credentialValidity) throws Exception {
        log.info("[mimoto] Starting downloadCredentialAsPDF for issuerId: {}, credentialType: {}", issuerId, credentialType);
        
        // Retrieve the issuer configuration and log it
        IssuerDTO issuerConfig = issuerService.getIssuerConfig(issuerId);
        log.info("[mimoto] Issuer configuration: {}", issuerConfig);
        
        // Retrieve well-known configuration for the issuer and log it
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = issuerService.getIssuerWellknown(issuerId);
        log.info("[mimoto] Credential Issuer Well-Known Response: {}", credentialIssuerWellKnownResponse);
        
        // Retrieve the supported credential types and log it
        CredentialsSupportedResponse credentialsSupportedResponse = issuerService.getIssuerWellknownForCredentialType(issuerId, credentialType);
        log.info("[mimoto] Credentials Supported Response: {}", credentialsSupportedResponse);
        
        // Generate the VC Credential Request
        VCCredentialRequest vcCredentialRequest = generateVCCredentialRequestNew(issuerConfig, credentialIssuerWellKnownResponse, credentialsSupportedResponse, response.getAccess_token());
        log.info("[mimoto] Generated VC Credential Request: {}", vcCredentialRequest);
        
        // Download the credential and log the response
        VCCredentialResponse vcCredentialResponse = downloadCredential(credentialIssuerWellKnownResponse.getCredentialEndPoint(), vcCredentialRequest, response.getAccess_token());
        log.info("[mimoto] Downloaded VC Credential Response: {}", vcCredentialResponse);
        
        // Verify the credential
        boolean verificationStatus = true;
        // = issuerId.toLowerCase().contains("mock") || verifyCredential(vcCredentialResponse);
        log.info("[mimoto] Verification status: {}", verificationStatus);
        
        if (verificationStatus) {
            String dataShareUrl = "";
            if (QRCodeType.OnlineSharing.equals(issuerConfig.getQr_code_type())) {
                log.info("[mimoto] QR Code type is OnlineSharing. Storing data in data share.");
                String vcCredentialResponseStr = objectMapper.writeValueAsString(vcCredentialResponse);
                log.info("[mimoto] VC Credential Response String: {}", vcCredentialResponseStr);
                dataShareUrl = dataShareService.storeDataInDataShare(vcCredentialResponseStr, credentialValidity);
                log.info("[mimoto] DataShare URL: {}", dataShareUrl);
            }
            log.info("[mimoto] Generating PDF for verifiable credentials.");
            ByteArrayInputStream pdfStream = generatePdfForVerifiableCredentials(vcCredentialResponse, issuerConfig, credentialsSupportedResponse, dataShareUrl, credentialValidity);
            log.info("[mimoto] PDF generation complete.");
            return pdfStream;
        }
        
        log.error("[mimoto] Credential verification failed for issuerId: {}, credentialType: {}", issuerId, credentialType);
        throw new VCVerificationException(SIGNATURE_VERIFICATION_EXCEPTION.getErrorCode(),
                SIGNATURE_VERIFICATION_EXCEPTION.getErrorMessage());
    }
    
    public VCCredentialResponse downloadCredential(String credentialEndpoint, VCCredentialRequest vcCredentialRequest, String accessToken) throws InvalidCredentialResourceException {
        log.info("[mimoto] Starting credential download");
        log.info("[mimoto] Credential Endpoint: {}", credentialEndpoint);
        log.info("[mimoto] VC Credential Request: {}", vcCredentialRequest);
        log.info("[mimoto] Access Token: {}",accessToken);
    
        fetchUserInfoAsString(accessToken);

        VCCredentialResponse vcCredentialResponse=null;
        try {
            vcCredentialResponse = restApiClient.postApi(credentialEndpoint, MediaType.APPLICATION_JSON,
                    vcCredentialRequest, VCCredentialResponse.class, accessToken);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        log.debug("[mimoto] VC Credential Response received: {}", vcCredentialResponse);
        
        if (vcCredentialResponse == null) {
            log.error("[mimoto] VC Credential Issue API not accessible, response is null");
            throw new RuntimeException("VC Credential Issue API not accessible");
        }
        
        log.info("[mimoto] Credential download completed successfully");
        return vcCredentialResponse;
    }

    public String fetchUserInfoAsString(String accessToken) {
        log.info("[mimoto] Starting fetchUserInfoAsString");
        String userInfoEndpoint = "https://stg-id.singpass.gov.sg/userinfo"; // Consider externalizing this URL
        log.info("[mimoto] UserInfo Endpoint: {}", userInfoEndpoint);
    
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        //accessToken="eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCIsImtpZCI6ImFsaWFzL3N0Zy1zcC1hdXRoLWFwaS1pZC10b2tlbi1zaWduaW5nLWtleS1rbXMtYXN5bW1ldHJpYy1rZXktYWxpYXMifQ.eyJzdWIiOiJ1PWI5MWU4ZTcyLThkNjYtNGIzNy1hNjc3LWNjNjIxZmM2MDI0YyIsImNsaWVudF9pZCI6InV0ZFZ2aEJXZTNyQkpadHVxZHVkeFoyTDBRd1VFcnpSIiwic2NvcGUiOiJvcGVuaWQgdWluZmluIG5hbWUgcmFjZSBkb2IiLCJqdGkiOiJhdC1LTm5lWDVpVFZEZnZiLWkyQUNqdmliMGVhN3Rob3FjMXFENXM4eEVONjhvIiwiaWF0IjoxNzQwNDY3OTIyLCJleHAiOjE3NDA0Njk3MjIsImF1ZCI6Imh0dHBzOi8vc3RnLWlkLnNpbmdwYXNzLmdvdi5zZy91c2VyaW5mbyIsImlzcyI6Imh0dHBzOi8vc3RnLWlkLnNpbmdwYXNzLmdvdi5zZyJ9.7yiaLSm2nrot7brWzzg4BmoOTRl9MX5Qdojp2FDMko8qDEjv-WLQhPcTSZpY-gPmfocsYJHsLFGa80wsbpR0TA";
        headers.set("Authorization", "Bearer " + accessToken);
        
        HttpEntity<String> entity = new HttpEntity<>(headers);
        log.info("[mimoto] Sending GET request to UserInfo endpoint");
        
        ResponseEntity<String> responseEntity = restTemplate.exchange(
            userInfoEndpoint,
            HttpMethod.GET,
            entity,
            String.class
        );
        
        log.info("[mimoto] Received response status: {}", responseEntity.getStatusCode());
        String responseBody = responseEntity.getBody();
        log.info("[mimoto] UserInfo response: {}", responseBody);

          // Your private encryption key in JWK format (from your config)
          String privateEncKeyJson = "{\n" +
          "  \"alg\": \"ECDH-ES+A256KW\",\n" +
          "  \"kty\": \"EC\",\n" +
          "  \"x\": \"_TSrfW3arG1Ebc8pCyT-r5lAFvCh_rJvC5HD5-y8yvs\",\n" +
          "  \"y\": \"Sr2vpuU6gzdUiXddGnRJIroXCfdameaR1mgU49H5h9A\",\n" +
          "  \"crv\": \"P-256\",\n" +
          "  \"d\": \"AEabUwi3VjOOfiyoOtSGrqpl8cfhcUhNtj-xh1l-UYE\",\n" +
          "  \"kid\": \"my-enc-key\"\n" +
          "}";
      try {
          // Parse the JWK into an ECKey using Nimbus
          ECKey privateEncKey = ECKey.parse(privateEncKeyJson);
          JSONObject userInfo = decodeUserInfo(responseBody, privateEncKey);
          System.out.println("Decoded User Info: " + userInfo.toString());
      } catch (Exception e) {
          System.err.println("Failed to decode token:");
          e.printStackTrace();
      }
        
        return responseBody;
    }
    
    public static JSONObject decodeUserInfo(String jweToken, ECKey privateEncKey) throws Exception {
        // Parse the JWE token
        JWEObject jweObject = JWEObject.parse(jweToken);
        System.out.println("[DEBUG] Parsed JWE Object: " + jweObject);
    
        // Decrypt the JWE token using your EC private key
        ECDHDecrypter decrypter = new ECDHDecrypter(privateEncKey.toECPrivateKey());
        jweObject.decrypt(decrypter);
        System.out.println("[DEBUG] JWE Decryption successful.");
    
        // The payload of the JWE is a JWS token (as a string)
        String jwsString = jweObject.getPayload().toString();
        System.out.println("[DEBUG] Extracted JWS Token: " + jwsString);
    
        // Parse the inner JWS token
        SignedJWT signedJWT = SignedJWT.parse(jwsString);
        // Optionally, verify the signature here with your public key.
        
        // Get the payload as a structured Map
        Map<String, Object> claimsMap = signedJWT.getJWTClaimsSet().toJSONObject();
        // Convert the Map to a JSONObject (using org.json.JSONObject)
        JSONObject claims = new JSONObject(claimsMap);
        System.out.println("[DEBUG] Decoded UserInfo (claims): " + claims.toString(2));
    
        return claims;
    }
    

    public VCCredentialRequest generateVCCredentialRequest(IssuerDTO issuerDTO, CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse, CredentialsSupportedResponse credentialsSupportedResponse, String accessToken) throws Exception {
        String jwt = joseUtil.generateJwt(credentialIssuerWellKnownResponse.getCredentialIssuer(), issuerDTO.getClient_id(), accessToken);
        return VCCredentialRequest.builder()
                .format(credentialsSupportedResponse.getFormat())
                .proof(VCCredentialRequestProof.builder()
                        .proofType(credentialsSupportedResponse.getProofTypesSupported().keySet().stream().findFirst().get())
                        .jwt(jwt)
                        .build())
                .credentialDefinition(VCCredentialDefinition.builder()
                        .type(credentialsSupportedResponse.getCredentialDefinition().getType())
                        .context(List.of("https://www.w3.org/2018/credentials/v1"))
                        .build())
                .build();
    }

    public VCCredentialRequest generateVCCredentialRequestNew(IssuerDTO issuerDTO, CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse, CredentialsSupportedResponse credentialsSupportedResponse, String accessToken) throws Exception {
        String jwt = joseUtil.generateJwt(credentialIssuerWellKnownResponse.getCredentialIssuer(), issuerDTO.getClient_id(), accessToken);
        return VCCredentialRequest.builder()
                .format(credentialsSupportedResponse.getFormat())
                .proof(VCCredentialRequestProof.builder()
                        .proofType(credentialsSupportedResponse.getProofTypesSupported().keySet().stream().findFirst().get())
                        .jwt(jwt)
                        .access_token(accessToken)
                        .build())
                .credentialDefinition(VCCredentialDefinition.builder()
                        .type(credentialsSupportedResponse.getCredentialDefinition().getType())
                        .context(List.of("https://www.w3.org/2018/credentials/v1"))
                        .build())
                .build();
    }

    public ByteArrayInputStream generatePdfForVerifiableCredentials(VCCredentialResponse vcCredentialResponse, IssuerDTO issuerDTO, CredentialsSupportedResponse credentialsSupportedResponse, String dataShareUrl, String credentialValidity) throws Exception {
        LinkedHashMap<String, Object> displayProperties = loadDisplayPropertiesFromWellknown(vcCredentialResponse, credentialsSupportedResponse);
        Map<String, Object> data = getPdfResourceFromVcProperties(displayProperties, credentialsSupportedResponse,  vcCredentialResponse, issuerDTO, dataShareUrl, credentialValidity);
        return renderVCInCredentialTemplate(data);
    }

    public Boolean verifyCredential(VCCredentialResponse vcCredentialResponse) throws VCVerificationException, JsonProcessingException {
        log.info("Initiated the VC Verification : Started");
        String credentialString = objectMapper.writeValueAsString(vcCredentialResponse.getCredential());
        VerificationResult verificationResult = credentialsVerifier.verify(credentialString, CredentialFormat.LDP_VC);
        if(!verificationResult.getVerificationStatus()){
            throw new VCVerificationException(verificationResult.getVerificationErrorCode().toLowerCase(), verificationResult.getVerificationMessage());
        }
        log.info("Completed the VC Verification : Completed -> result : " + verificationResult);
        return true;
    }

    @NotNull
    private static LinkedHashMap<String, Object> loadDisplayPropertiesFromWellknown(VCCredentialResponse vcCredentialResponse, CredentialsSupportedResponse credentialsSupportedResponse) {
        LinkedHashMap<String,Object> displayProperties = new LinkedHashMap<>();
        Map<String, Object> credentialProperties = vcCredentialResponse.getCredential().getCredentialSubject();

        LinkedHashMap<String, String> vcPropertiesFromWellKnown = new LinkedHashMap<>();
        Map<String, CredentialDisplayResponseDto> credentialSubject = credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject();
        credentialSubject.keySet().forEach(VCProperty -> vcPropertiesFromWellKnown.put(VCProperty, credentialSubject.get(VCProperty).getDisplay().get(0).getName()));

        List<String> orderProperty = credentialsSupportedResponse.getOrder();

        List<String> fieldProperties = orderProperty == null ? new ArrayList<>(vcPropertiesFromWellKnown.keySet()) : orderProperty;
        fieldProperties.forEach(vcProperty -> {
            if(credentialProperties.get(vcProperty) != null) {
                displayProperties.put(vcPropertiesFromWellKnown.get(vcProperty), credentialProperties.get(vcProperty));
            }
        });
        return displayProperties;
    }


    private Map<String, Object> getPdfResourceFromVcProperties(LinkedHashMap<String, Object> displayProperties, CredentialsSupportedResponse credentialsSupportedResponse, VCCredentialResponse  vcCredentialResponse, IssuerDTO issuerDTO, String dataShareUrl, String credentialValidity) throws IOException, WriterException {
        Map<String, Object> data = new HashMap<>();
        LinkedHashMap<String, Object> rowProperties = new LinkedHashMap<>();
        String backgroundColor = credentialsSupportedResponse.getDisplay().get(0).getBackgroundColor();
        String backgroundImage = credentialsSupportedResponse.getDisplay().get(0).getBackgroundImage().getUri();
        String textColor = credentialsSupportedResponse.getDisplay().get(0).getTextColor();
        String credentialSupportedType = credentialsSupportedResponse.getDisplay().get(0).getName();
        String face = vcCredentialResponse.getCredential().getCredentialSubject().get("face") != null ? (String) vcCredentialResponse.getCredential().getCredentialSubject().get("face") : null;

        displayProperties.entrySet().stream()
                .forEachOrdered(entry -> {
                    if(entry.getValue() instanceof Map) {
                        rowProperties.put(entry.getKey(), ((Map<?, ?>) entry.getValue()).get("value"));
                    } else if(entry.getValue() instanceof List) {
                        String value = "";
                        if( ((List<?>) entry.getValue()).get(0) instanceof String) {
                            value = ((List<String>) entry.getValue()).stream().reduce((field1, field2) -> field1 + ", " + field2 ).get();
                        } else {
                            value = (String) ((Map<?, ?>) ((List<?>) entry.getValue()).get(0)).get("value");
                        }
                        rowProperties.put(entry.getKey(), value);
                    } else {
                        rowProperties.put(entry.getKey(), entry.getValue());
                    }
                });

        String qrCodeImage = QRCodeType.OnlineSharing.equals(issuerDTO.getQr_code_type()) ? constructQRCodeWithAuthorizeRequest(vcCredentialResponse, dataShareUrl) :
                QRCodeType.EmbeddedVC.equals(issuerDTO.getQr_code_type()) ? constructQRCodeWithVCData(vcCredentialResponse) : "";
        data.put("qrCodeImage", qrCodeImage);
        data.put("credentialValidity", credentialValidity);
        data.put("logoUrl", issuerDTO.getDisplay().stream().map(d -> d.getLogo().getUrl()).findFirst().orElse(""));
        data.put("rowProperties", rowProperties);
        data.put("textColor", textColor);
        data.put("backgroundColor", backgroundColor);
        data.put("backgroundImage", backgroundImage);
        data.put("titleName", credentialSupportedType);
        data.put("face", face);
        return data;
    }

    @NotNull
    private ByteArrayInputStream renderVCInCredentialTemplate(Map<String, Object> data) throws IOException {
        String  credentialTemplate = utilities.getCredentialSupportedTemplateString();

        Properties props = new Properties();
        props.setProperty("resource.loader", "class");
        props.setProperty("class.resource.loader.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
        Velocity.init(props);
        VelocityContext velocityContext = new VelocityContext(data);

        // Merge the context with the template
        StringWriter writer = new StringWriter();
        Velocity.evaluate(velocityContext, writer, "Credential Template", credentialTemplate);

        // Get the merged HTML string
        String mergedHtml = writer.toString();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        PdfWriter pdfwriter = new PdfWriter(outputStream);
        DefaultFontProvider defaultFont = new DefaultFontProvider(true, false, false);
        ConverterProperties converterProperties = new ConverterProperties();
        converterProperties.setFontProvider(defaultFont);
        HtmlConverter.convertToPdf(mergedHtml, pdfwriter, converterProperties);
        return new ByteArrayInputStream(outputStream.toByteArray());
    }

    private String constructQRCode(String qrData) throws WriterException {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(qrData, BarcodeFormat.QR_CODE, qrCodeWidth, qrCodeHeight);
        BufferedImage qrImage = MatrixToImageWriter.toBufferedImage(bitMatrix);
        return Utilities.encodeToString(qrImage, "png");
    }

    private String constructQRCodeWithVCData(VCCredentialResponse vcCredentialResponse) throws JsonProcessingException, WriterException {
        String qrData = pixelPass.generateQRData(objectMapper.writeValueAsString(vcCredentialResponse.getCredential()), "");
        if(allowedQRDataSizeLimit > qrData.length()){
            return constructQRCode(qrData);
        }
       return "";
    }
    private String constructQRCodeWithAuthorizeRequest(VCCredentialResponse vcCredentialResponse, String dataShareUrl) throws WriterException, JsonProcessingException {
        PresentationDefinitionDTO presentationDefinitionDTO = presentationService.constructPresentationDefinition(vcCredentialResponse);
        String presentationString = objectMapper.writeValueAsString(presentationDefinitionDTO);
        String qrData = String.format(ovpQRDataPattern, URLEncoder.encode(dataShareUrl, StandardCharsets.UTF_8), URLEncoder.encode(presentationString, StandardCharsets.UTF_8));
        return constructQRCode(qrData);
    }
}
