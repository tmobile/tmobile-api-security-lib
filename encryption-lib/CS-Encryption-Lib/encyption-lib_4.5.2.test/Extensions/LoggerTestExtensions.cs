///*
// * Copyright 2020 T-Mobile US, Inc.
// *
// * Licensed under the Apache License, Version 2.0 (the "License");
// * you may not use this file except in compliance with the License.
// * You may obtain a copy of the License at
// *
// *     http://www.apache.org/licenses/LICENSE-2.0
// *
// * Unless required by applicable law or agreed to in writing, software
// * distributed under the License is distributed on an "AS IS" BASIS,
// * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// * See the License for the specific language governing permissions and
// * limitations under the License.
// */

//using Moq;
//using System;

//namespace com.tmobile.oss.security.taap.jwe.test.Extensions
//{
//    public static class LoggerTestExtensions
//    {
//        public static Mock<ILogger<T>> VerifyDebugWasCalled<T>(this Mock<ILogger<T>> logger, string expectedMessage)
//        {
//            Func<object, Type, bool> state = (v, t) => v.ToString().CompareTo(expectedMessage) == 0;

//            logger.Verify(
//                x => x.Log(
//                    It.Is<LogLevel>(l => l == LogLevel.Debug),
//                    It.IsAny<EventId>(),
//                    It.Is<It.IsAnyType>((v, t) => state(v, t)),
//                    It.IsAny<Exception>(),
//                    It.Is<Func<It.IsAnyType, Exception, string>>((v, t) => true)));

//            return logger;
//        }

//        public static Mock<ILogger<T>> VerifyDebugWasCalled<T>(this Mock<ILogger<T>> logger)
//        {
//            logger.Verify(
//                x => x.Log(
//                    It.Is<LogLevel>(l => l == LogLevel.Debug),
//                    It.IsAny<EventId>(),
//                    It.Is<It.IsAnyType>((v, t) => true),
//                    It.IsAny<Exception>(),
//                    It.Is<Func<It.IsAnyType, Exception, string>>((v, t) => true)));

//            return logger;
//        }

//        public static Mock<ILogger<T>> VerifyLogging<T>(this Mock<ILogger<T>> logger, string expectedMessage, LogLevel expectedLogLevel = LogLevel.Debug, Times? times = null)
//        {
//            if (times == null)
//            {
//                times = Times.Once();
//            }
    
//            Func<object, Type, bool> state = (v, t) => v.ToString().CompareTo(expectedMessage) == 0;

//            logger.Verify(
//                x => x.Log(
//                    It.Is<LogLevel>(l => l == expectedLogLevel),
//                    It.IsAny<EventId>(),
//                    It.Is<It.IsAnyType>((v, t) => state(v, t)),
//                    It.IsAny<Exception>(),
//                    It.Is<Func<It.IsAnyType, Exception, string>>((v, t) => true)), (Times)times);

//            return logger;
//        }
//    }
//}
