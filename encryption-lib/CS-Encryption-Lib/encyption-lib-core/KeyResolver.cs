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

using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Timers;

namespace com.tmobile.oss.security.taap.jwe
{
	/// <summary>
	/// Key Resolver
	/// </summary>
	public class KeyResolver : IKeyResolver, IDisposable
	{
		private readonly IJwksService jwksService;
		private IList<JsonWebKey> publicJsonWebKeyList;
		private readonly long cacheDurationSeconds;
		private readonly Timer timer;
		private bool IsCacheExpired;
		private IList<JsonWebKey> privateJsonWebKeyList;
		private bool disposed = false;

		public KeyResolver(IList<JsonWebKey> privateJsonWebKeyList, IJwksService jwksService, long cacheDurationSeconds)
		{
			this.privateJsonWebKeyList = privateJsonWebKeyList;
			this.jwksService = jwksService;
			this.cacheDurationSeconds = cacheDurationSeconds;

			this.IsCacheExpired = true;
			this.timer = new Timer(this.cacheDurationSeconds * 1000); // Milliseconds
			this.timer.Elapsed += OnTimedEvent;
			this.timer.AutoReset = false;
			this.timer.Enabled = false;
		}

		/// <summary>
		/// Get Encryption Key Async
		/// </summary>
		/// <returns>Json Web Key</returns>
		public async Task<JsonWebKey> GetEncryptionKeyAsync()
		{
			JsonWebKey jsonWebKey = null;

			if (this.IsCacheExpired)
			{
				this.publicJsonWebKeyList = await jwksService.GetJsonWebKeyListAsync();
				this.IsCacheExpired = false;
				this.timer.Enabled = true;
			}

			// Get first EC key
			jsonWebKey = this.publicJsonWebKeyList.FirstOrDefault(k => k.Kty == "EC");
			if (jsonWebKey == null)
			{
				// If no EC key, then get RSA key
				jsonWebKey = this.publicJsonWebKeyList.FirstOrDefault(k => k.Kty == "RSA");
				if (jsonWebKey == null)
				{
					throw new EncryptionException("Unable to retrieve public EC or RSA key from JWK store.");
				}
			}

			return jsonWebKey;
		}

		public async Task<JsonWebKey> GetDecryptionKeyAsync(string kid)
		{
			var privateJsonWebKey = this.privateJsonWebKeyList.Where(p => p.Kid == kid)
									                          .FirstOrDefault();
			return await Task.FromResult(privateJsonWebKey);
		}

		private void OnTimedEvent(Object source, ElapsedEventArgs e)
		{
			this.IsCacheExpired = true;
			this.timer.Enabled = false;
		}

		public void Dispose()
		{
			Dispose(true);
			//GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool disposing)
		{
			if (!this.disposed)
			{
				if (disposing)
				{
					this.timer.Dispose();
				}

				disposed = true;
			}
		}
	}
}
