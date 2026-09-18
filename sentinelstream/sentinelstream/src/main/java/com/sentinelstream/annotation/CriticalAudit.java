package com.sentinelstream.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a {@link com.sentinelstream.rules.SecurityRule} implementation as
 * security-sensitive. Rules tagged with this annotation:
 *
 *  1. Are always loaded eagerly by {@link com.sentinelstream.rules.RuleLoader}
 *     via reflection, regardless of any "lite mode" configuration.
 *  2. Have every match they produce written to the audit trail, in addition
 *     to the normal incident report flow.
 *
 * RUNTIME retention is required because RuleLoader inspects rule classes
 * with reflection at application startup, not at compile time.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface CriticalAudit {

    /** Free-text justification for why this rule is considered critical. */
    String reason() default "Detects high-impact security threats";

    /** Whether a match from this rule should page an on-call analyst. */
    boolean pageOnCall() default false;
}
