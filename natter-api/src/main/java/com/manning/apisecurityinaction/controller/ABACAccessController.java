package com.manning.apisecurityinaction.controller;

import java.time.LocalTime;
import java.util.*;

import spark.*;

import static spark.Spark.halt;

public abstract class ABACAccessController {

    public void enforcePolicy(Request request, Response response) {

        var subjectAttrs = new HashMap<String, Object>();
        subjectAttrs.put("user", request.attribute("subject"));
        subjectAttrs.put("groups", request.attribute("groups"));

        var resourceAttrs = new HashMap<String, Object>();
        resourceAttrs.put("path", request.pathInfo());
        resourceAttrs.put("space", request.params(":spaceId"));

        var actionAttrs = new HashMap<String, Object>();
        actionAttrs.put("method", request.requestMethod());

        var envAttrs = new HashMap<String, Object>();
        envAttrs.put("timeOfDay", LocalTime.now());
        envAttrs.put("ip", request.ip());

        var permitted = checkPermitted(subjectAttrs, resourceAttrs,
                actionAttrs, envAttrs);

        if (!permitted) {
            halt(403);
        }
    }

    abstract boolean checkPermitted(
            Map<String, Object> subject,
            Map<String, Object> resource,
            Map<String, Object> action,
            Map<String, Object> env);

    public static class Decision {
        private boolean permit = true;

        public void deny() {
            permit = false;
        }

        public void permit() {
        }

        boolean isPermitted() {
            return permit;
        }
    }
}
