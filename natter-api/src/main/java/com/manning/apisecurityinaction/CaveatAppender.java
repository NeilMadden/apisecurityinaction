package com.manning.apisecurityinaction;

import com.github.nitram509.jmacaroons.MacaroonsBuilder;

import static com.github.nitram509.jmacaroons.MacaroonsBuilder.deserialize;

public class CaveatAppender {
    public static void main(String... args) {
        var builder = new MacaroonsBuilder(deserialize(args[0]));
        for (int i = 1; i < args.length; ++i) {
            var caveat = args[i];
            builder.add_first_party_caveat(caveat);
        }
        System.out.println(builder.getMacaroon().serialize());
    }
}
