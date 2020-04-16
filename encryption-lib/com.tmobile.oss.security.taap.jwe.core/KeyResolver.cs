using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Timers;

[assembly: InternalsVisibleTo("com.tmobile.oss.security.taap.jwe.test")]
namespace com.tmobile.oss.security.taap.jwe
{
	/// <summary>
	/// Key Resolver
	/// </summary>
	internal class KeyResolver : IKeyResolver
	{
		private readonly IJwksService jwksService;
		private IList<JsonWebKey> publicJsonWebKeyList;
		private readonly long cacheDurationSeconds;
		private readonly Timer timer;
		private bool IsCacheExpired;
		private IList<JsonWebKey> privateJsonWebKeyList;

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
			timer.Enabled = false;
		}
	}
}
