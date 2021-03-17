/*
 * Copyright 2020 T-Mobile US, Inc.
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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics;

namespace com.tmobile.oss.security.taap.jwe.test
{
    public class ExpectedExceptionMessageAttribute : ExpectedExceptionBaseAttribute
    {
        public Type ExceptionType { get; set; }

        public string ExpectedMessage { get; set; }

        public ExpectedExceptionMessageAttribute(Type exceptionType)
        {
            this.ExceptionType = exceptionType;
        }

        public ExpectedExceptionMessageAttribute(Type exceptionType, string expectedMessage)
        {
            this.ExceptionType = exceptionType;
            this.ExpectedMessage = expectedMessage;
        }

        protected override void Verify(Exception e)
        {
            if (e.GetType() != this.ExceptionType)
            {
                Assert.Fail($"ExpectedExceptionMessageAttribute failed. Expected exception type: {this.ExceptionType.FullName}. " +
                    $"Actual exception type: {e.GetType().FullName}. Exception message: {e.Message}");
            }

            var actualMessage = e.Message.Trim();
            if (this.ExpectedMessage != null)
            {
                Assert.AreEqual(this.ExpectedMessage, actualMessage);
            }

            // Debug.WriteLine($"ExpectedExceptionMessageAttribute:{actualMessage}");
        }
    }
}
