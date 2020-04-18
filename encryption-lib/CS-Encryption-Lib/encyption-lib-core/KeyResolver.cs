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
using System.Threading;
using System.Threading.Tasks;
using System.Timers;
using Timer = System.Timers.Timer;

namespace com.tmobile.oss.security.taap.jwe
{
	/// <summary>
	/// Key Resolver
	/// </summary>
	public class KeyResolver : IKeyResolver, IDisposable
	{
		private long cacheDurationSeconds;
		private List<JsonWebKey> publicJsonWebKeyList;
		private List<JsonWebKey> privateJsonWebKeyList;
		private JwksService jwksService;
		private bool IsCacheExpired;

		private Timer timer;
		private bool disposed;

		private int jwksServiceCallCount;

		/// <summary>
		/// Default Constructor
		/// </summary>
		private KeyResolver()
		{
			this.cacheDurationSeconds = 3600; // Default to 1 Hour
			this.privateJsonWebKeyList = new List<JsonWebKey>();
			this.IsCacheExpired = true;
			this.disposed = false;
		}

		/// <summary>
		/// Custom Constructor
		/// </summary>
		public KeyResolver(long cacheDurationSeconds) : base()
		{
			this.cacheDurationSeconds = cacheDurationSeconds;
		}

		/// <summary>
		/// Get Public JsonWebKey List
		/// </summary>
		/// <returns></returns>
		public List<JsonWebKey> GetPublicJsonWebKeyList()
		{
			List<JsonWebKey> publicJsonWebKeyList = null;
			Interlocked.Exchange(ref publicJsonWebKeyList, this.publicJsonWebKeyList);
			return publicJsonWebKeyList;
		}

		/// <summary>
		/// Set Public JsonWebKey List
		/// </summary>
		/// <param name="publicJsonWebKeyList"></param>
		public void SetPublicJsonWebKeyList(List<JsonWebKey> publicJsonWebKeyList)
		{
			Interlocked.Exchange(ref this.publicJsonWebKeyList, publicJsonWebKeyList);
		}

		/// <summary>
		/// Get Private JsonWebKey List
		/// </summary>
		/// <returns></returns>
		public List<JsonWebKey> GetPrivateJsonWebKeyList()
		{
			List<JsonWebKey> privateJsonWebKeyList = null;
			Interlocked.Exchange(ref privateJsonWebKeyList, this.privateJsonWebKeyList);
			return privateJsonWebKeyList;
		}

		/// <summary>
		/// Set Private JsonWebKey List
		/// </summary>
		/// <param name="privateJsonWebKeyList"></param>
		public void SetPrivateJsonWebKeyList(List<JsonWebKey> privateJsonWebKeyList)
		{
			Interlocked.Exchange(ref this.privateJsonWebKeyList, privateJsonWebKeyList);
		}

		/// <summary>
		/// Get JwksService
		/// </summary>
		/// <returns>JwksService</returns>
		public JwksService GetJwksService()
		{
			JwksService jwksService = null;
			Interlocked.Exchange(ref jwksService, this.jwksService);
			return jwksService;
		}

		/// <summary>
		/// Set JwksService
		/// </summary>
		/// <param name="jwksService">JwksService</param>
		public void SetJwksService(JwksService jwksService)
		{
			Interlocked.Exchange(ref this.jwksService, jwksService);

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
			var jsonWebKey = default(JsonWebKey);
			var publicJsonWebKeyList = new List<JsonWebKey>();

			if (this.IsCacheExpired)
			{
				// Only allow one thread at a time to call JWKS service
				if (Interlocked.Increment(ref this.jwksServiceCallCount) == 1)
				{
					try
					{
						publicJsonWebKeyList = await jwksService.GetJsonWebKeyListAsync();
						this.SetPublicJsonWebKeyList(publicJsonWebKeyList);
						this.IsCacheExpired = false;
						this.timer.Enabled = true;
					}
					finally
					{
						Interlocked.Exchange(ref this.jwksServiceCallCount, 0);
					}
				}
			}

			publicJsonWebKeyList = this.GetPublicJsonWebKeyList();
			jsonWebKey = publicJsonWebKeyList.FirstOrDefault(k => k.Kty == "EC");
			if (jsonWebKey == null)
			{
				jsonWebKey = publicJsonWebKeyList.FirstOrDefault(k => k.Kty == "RSA");
				if (jsonWebKey == null)
				{
					throw new EncryptionException("Unable to retrieve public EC or RSA key from JWK store.");
				}
			}

			return jsonWebKey;
		}

		public async Task<JsonWebKey> GetDecryptionKeyAsync(string kid)
		{
			var privateJsonWebKey = this.GetPrivateJsonWebKeyList().Where(p => p.Kid == kid)
									                               .FirstOrDefault();
			return await Task.FromResult(privateJsonWebKey);
		}

		public void Dispose()
		{
			Dispose(true);
		}

		protected virtual void Dispose(bool disposing)
		{
			if (!this.disposed)
			{
				if (disposing)
				{
					this.timer.Dispose();
				}

				this.disposed = true;
			}
		}

		private void OnTimedEvent(Object source, ElapsedEventArgs e)
		{
			this.IsCacheExpired = true;
			this.timer.Enabled = false;
		}
	}
}
