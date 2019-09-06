/*
 * Copyright 2019 T-Mobile US, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
