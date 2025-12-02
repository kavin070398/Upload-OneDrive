package learn.isPossible.upload.onedrive.config;

import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.microsoft.graph.authentication.TokenCredentialAuthProvider;
import com.microsoft.graph.requests.GraphServiceClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Slf4j
@Configuration
public class GraphConfig {

    @Value("${azure.client-id}")
    private String clientId;

    @Value("${azure.client-secret}")
    private String clientSecret;

    @Value("${azure.tenant-id}")
    private String tenantId;

    @Bean
    public GraphServiceClient<?> graphClient() {

        log.debug("client-id: " + clientId);
        log.debug("client-secret: " + clientSecret);
        log.debug("tenant-id: " + tenantId);

        ClientSecretCredential credential = new ClientSecretCredentialBuilder()
                .clientId(clientId)
                .clientSecret(clientSecret)
                .tenantId(tenantId)
                .build();

        TokenCredentialAuthProvider authProvider =
                new TokenCredentialAuthProvider(
                        List.of("https://graph.microsoft.com/.default"),
                        credential);

        return GraphServiceClient.builder()
                .authenticationProvider(authProvider)
                .buildClient();
    }
}
