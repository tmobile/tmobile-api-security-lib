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

using System;

namespace com.tmobile.oss.security.taap.poptoken.builder
{
	/// <summary>
	/// This exception is thrown when there is an error while building the PoP token.
	/// <para>
	/// This is also a base class for all the PoP builder related custom exceptions.
	/// </para>
	/// </summary>
	public class PopTokenBuilderException : Exception
	{
		/// <summary>
		/// Constructs the PopTokenBuilderException using the specified message.
		/// </summary>
		/// <param name="message"> The exception message </param>
		public PopTokenBuilderException(string message) :
			base(message)
		{
		}

		/// <summary>
		/// Constructs the PopTokenBuilderException using the specified message and cause.
		/// </summary>
		/// <param name="message"> The exception message </param>
		/// <param name="cause"> The cause of the exception </param>
		public PopTokenBuilderException(string message, Exception cause) : 
			base(message, cause)
		{
		}
	}
}
