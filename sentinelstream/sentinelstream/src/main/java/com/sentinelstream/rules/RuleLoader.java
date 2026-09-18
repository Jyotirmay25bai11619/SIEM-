package com.sentinelstream.rules;

import com.sentinelstream.annotation.CriticalAudit;

import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Dynamically instantiates SecurityRule implementations at runtime using
 * Java Reflection, rather than hard-coding a fixed list of {@code new Foo()}
 * calls. This is what lets an operator drop a new detector class on the
 * classpath (fully-qualified name added to application.properties) without
 * recompiling Main.
 *
 * Each call to {@link #loadFreshInstances()} returns brand-new rule objects
 * because rule state (e.g. per-IP failure stacks) must not be shared across
 * consumer threads -- every consumer thread calls this once at startup to
 * get its own private rule set.
 */
public class RuleLoader {

    private static final Logger LOGGER = Logger.getLogger(RuleLoader.class.getName());

    // In a fuller deployment these fully-qualified class names would be read
    // from application.properties; kept as a constant here for a reliable,
    // dependency-free "flawless run out of the box" demo.
    private static final String[] DEFAULT_RULE_CLASSES = {
            "com.sentinelstream.rules.BruteForceDetector",
            "com.sentinelstream.rules.DataExfiltrationDetector",
            "com.sentinelstream.rules.SqlInjectionDetector",
            "com.sentinelstream.rules.PathTraversalDetector"
    };

    public List<SecurityRule> loadFreshInstances() {
        List<SecurityRule> rules = new ArrayList<>();

        for (String className : DEFAULT_RULE_CLASSES) {
            try {
                Class<?> clazz = Class.forName(className);

                if (!SecurityRule.class.isAssignableFrom(clazz)) {
                    LOGGER.warning(() -> className + " does not extend SecurityRule, skipping");
                    continue;
                }

                if (clazz.isAnnotationPresent(CriticalAudit.class)) {
                    CriticalAudit audit = clazz.getAnnotation(CriticalAudit.class);
                    LOGGER.info(() -> String.format(
                            "Loading @CriticalAudit rule %s (reason=\"%s\", pageOnCall=%s)",
                            clazz.getSimpleName(), audit.reason(), audit.pageOnCall()));
                }

                Constructor<?> constructor = clazz.getDeclaredConstructor();
                Object instance = constructor.newInstance();
                rules.add((SecurityRule) instance);

            } catch (ClassNotFoundException e) {
                LOGGER.log(Level.SEVERE, "Rule class not found on classpath: " + className, e);
            } catch (ReflectiveOperationException e) {
                LOGGER.log(Level.SEVERE, "Failed to instantiate rule via reflection: " + className, e);
            }
        }

        if (rules.isEmpty()) {
            LOGGER.warning("No security rules were loaded -- pipeline will run in pass-through mode.");
        }

        return rules;
    }

    public static List<String> getConfiguredRuleClassNames() {
        return Arrays.asList(DEFAULT_RULE_CLASSES);
    }
}
