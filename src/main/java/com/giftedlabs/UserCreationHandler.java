package com.giftedlabs;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.GetParameterRequest;
import software.amazon.awssdk.services.ssm.model.GetParameterResponse;

import java.util.Map;

public class UserCreationHandler implements RequestHandler<Map<String, Object>, String> {
    private static final Logger logger = LoggerFactory.getLogger(UserCreationHandler.class);

    // Replace these with the names you used in CloudFormation
    private static final String EC2_USER_EMAIL_PARAM = "/users/ec2-user/email";
    private static final String S3_USER_EMAIL_PARAM = "/users/s3-user/email";
    private static final String ONE_TIME_PASSWORD_SECRET = "OneTimePasswordSecret";

    @Override
    public String handleRequest(Map<String, Object> event, Context context) {
        logger.info("Received event: {}", event);

        // Extract userName from the event detail (adjust depending on CloudTrail event structure)
        Map<String, Object> detail = (Map<String, Object>) event.get("detail");
        if (detail == null) {
            logger.warn("No detail found in event.");
            return "No detail";
        }
        String userName = (String) detail.get("userName");
        logger.info("New IAM user created: {}", userName);

        // Initialize AWS SDK clients
        Region region = Region.of(System.getenv("AWS_REGION"));
        try (SsmClient ssmClient = SsmClient.builder().region(region).build();
             SecretsManagerClient secretsClient = SecretsManagerClient.builder().region(region).build()) {

            String userEmail;
            if ("ec2-user".equals(userName)) {
                userEmail = getParameterValue(ssmClient, EC2_USER_EMAIL_PARAM);
            } else if ("s3-user".equals(userName)) {
                userEmail = getParameterValue(ssmClient, S3_USER_EMAIL_PARAM);
            } else {
                userEmail = "Not configured";
            }
            logger.info("User email: {}", userEmail);

            // Retrieve the one-time password from Secrets Manager
            String password = getSecretValue(secretsClient, ONE_TIME_PASSWORD_SECRET, "password");
            logger.info("One-time password for {}: {}", userName, password);
        } catch (Exception e) {
            logger.error("Error retrieving parameters or secrets: ", e);
        }
        return "Processed event for user: " + userName;
    }

    private String getParameterValue(SsmClient ssmClient, String parameterName) {
        GetParameterRequest paramRequest = GetParameterRequest.builder()
                .name(parameterName)
                .withDecryption(true)
                .build();
        GetParameterResponse response = ssmClient.getParameter(paramRequest);
        return response.parameter().value();
    }

    private String getSecretValue(SecretsManagerClient secretsClient, String secretName, String jsonKey) {
        GetSecretValueRequest secretRequest = GetSecretValueRequest.builder()
                .secretId(secretName)
                .build();
        GetSecretValueResponse response = secretsClient.getSecretValue(secretRequest);
        // In our secret we store JSON like {"password":"<value>"}. For simplicity, we do a basic extraction.
        String secretString = response.secretString();
        // Simple extraction (in production, use a JSON parser)
        String keyPattern = "\"" + jsonKey + "\":\"";
        int start = secretString.indexOf(keyPattern) + keyPattern.length();
        int end = secretString.indexOf("\"", start);
        return secretString.substring(start, end);
    }
}
