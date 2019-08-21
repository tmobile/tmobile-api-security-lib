package com.tmobile.oss.security.taap.poptoken.validator.demo;

import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import org.junit.runner.RunWith;
import org.junit.runner.notification.Failure;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RunWith(Suite.class)
@SuiteClasses({ //
        // run for first time
        PopTokenValidatorDemoWithNoRequestPayloadPerfTest.class, //
        PopTokenValidatorDemoWith1KilobyteRequestPayloadPerfTest.class, //
        PopTokenValidatorDemoWith10KilobyteRequestPayloadPerfTest.class, //
        PopTokenValidatorDemoWith100KilobyteRequestPayloadPerfTest.class, //
        PopTokenValidatorDemoWith1MegabyteRequestPayloadPerfTest.class, //

        // run for second time and use the numbers from 2nd run to remove the JVM bootstrap processing
        PopTokenValidatorDemoWithNoRequestPayloadPerfTest.class, //
        PopTokenValidatorDemoWith1KilobyteRequestPayloadPerfTest.class, //
        PopTokenValidatorDemoWith10KilobyteRequestPayloadPerfTest.class, //
        PopTokenValidatorDemoWith100KilobyteRequestPayloadPerfTest.class, //
        PopTokenValidatorDemoWith1MegabyteRequestPayloadPerfTest.class //
}) //
public class PopTokenValidatorPerfTestSuite {

    private static final Logger logger = LoggerFactory.getLogger(PopTokenValidatorPerfTestSuite.class);

    public static void main(String args[]) {
        Result result = JUnitCore.runClasses(PopTokenValidatorPerfTestSuite.class);

        for (Failure failure : result.getFailures()) {
            logger.error(failure.toString());
        }
        logger.info(result.wasSuccessful() ? "Test suite ran successfully" : "");
    }
}
