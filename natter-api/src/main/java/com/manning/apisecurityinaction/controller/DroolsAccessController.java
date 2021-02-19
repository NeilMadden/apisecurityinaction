package com.manning.apisecurityinaction.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.kie.api.KieServices;
import org.kie.api.runtime.KieContainer;

public class DroolsAccessController extends ABACAccessController {

    private final KieContainer kieContainer;

    public DroolsAccessController() {
        this.kieContainer = KieServices.get().getKieClasspathContainer();
    }

    @Override
    boolean checkPermitted(Map<String, Object> subject,
                           Map<String, Object> resource,
                           Map<String, Object> action,
                           Map<String, Object> env) {

        var session = kieContainer.newStatelessKieSession();
        var decision = new Decision();
        session.setGlobal("decision", decision);

        session.execute(List.of(
                new Subject(subject),
                new Resource(resource),
                new Action(action),
                new Environment(env)));

        return decision.isPermitted();
    }

    public static class Subject extends HashMap<String, Object> {
        Subject(Map<String, Object> m) { super(m); }
    }

    public static class Resource extends HashMap<String, Object> {
        Resource(Map<String, Object> m) { super(m); }
    }

    public static class Action extends HashMap<String, Object> {
        Action(Map<String, Object> m) { super(m); }
    }

    public static class Environment extends HashMap<String, Object> {
        Environment(Map<String, Object> m) { super(m); }
    }
}
