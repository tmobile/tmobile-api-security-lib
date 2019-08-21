package com.tmobile.oss.security.taap.poptoken.builder.demo;

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
        PopTokenBuilderDemoWithNoRequestPayloadPerfTest.class, //
        PopTokenBuilderDemoWith1KilobyteRequestPayloadPerfTest.class, //
        PopTokenBuilderDemoWith10KilobyteRequestPayloadPerfTest.class, //
        PopTokenBuilderDemoWith100KilobyteRequestPayloadPerfTest.class, //
        PopTokenBuilderDemoWith1MegabyteRequestPayloadPerfTest.class, //

        // run for second time and use the numbers from 2nd run to remove the JVM bootstrap processing
        PopTokenBuilderDemoWithNoRequestPayloadPerfTest.class, //
        PopTokenBuilderDemoWith1KilobyteRequestPayloadPerfTest.class, //
        PopTokenBuilderDemoWith10KilobyteRequestPayloadPerfTest.class, //
        PopTokenBuilderDemoWith100KilobyteRequestPayloadPerfTest.class, //
        PopTokenBuilderDemoWith1MegabyteRequestPayloadPerfTest.class //
}) //
public class PopTokenBuilderPerfTestSuite {

    private static final Logger logger = LoggerFactory.getLogger(PopTokenBuilderPerfTestSuite.class);

    public static void main(String args[]) {
        Result result = JUnitCore.runClasses(PopTokenBuilderPerfTestSuite.class);

        for (Failure failure : result.getFailures()) {
            logger.error(failure.toString());
        }
        logger.info(result.wasSuccessful() ? "Test suite ran successfully" : "");
    }
}
