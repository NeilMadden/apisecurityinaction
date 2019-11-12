package com.manning.apisecurityinaction;

import com.manning.apisecurityinaction.token.DatabaseTokenStore;
import com.manning.apisecurityinaction.token.TokenStore.Token;
import org.dalesbred.Database;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.JSONObject;
import org.slf4j.*;

import static spark.Spark.*;

public class TokenService {
    private static final Logger logger =
            LoggerFactory.getLogger(TokenService.class);

    public static void main(String... args) throws Exception {
        secure("/etc/certs/natter-token-service/natter-token-service.p12",
            "changeit", null, null);
        var jdbcUrl =
            "jdbc:h2:ssl://natter-token-database-service:9092/mem:tokens";
        var datasource = JdbcConnectionPool.create(
                jdbcUrl, "natter", "password");
        Main.createTables(datasource.getConnection());
        datasource = JdbcConnectionPool.create(
                jdbcUrl, "natter_api_user", "password");
        var database = Database.forDataSource(datasource);
        var tokenStore = new DatabaseTokenStore(database);

        afterAfter((request, response) -> {
            response.header("Content-Type", "application/json");
        });

        post("/tokens", (request, response) -> {
            var json = new JSONObject(request.body());
            var token = Token.fromJson(json);
            var tokenId = tokenStore.create(request, token);
            logger.info("Created token for user: {}", token.username);
            return new JSONObject().put("tokenId", tokenId);
        });

        get("/tokens/:tokenId", (request, response) -> {
            logger.info("Validating token");
            var tokenId = request.params(":tokenId");
            return tokenStore.read(request, tokenId)
                    .map(Token::toJson)
                    .orElseGet(() -> {
                        response.status(404);
                        return new JSONObject();
                    });
        });

        delete("/tokens/:tokenId", (request, response) -> {
            var tokenId = request.params(":tokenId");
            logger.info("Revoking token: {}", tokenId);
            tokenStore.revoke(request, tokenId);
            return new JSONObject();
        });
    }
}
