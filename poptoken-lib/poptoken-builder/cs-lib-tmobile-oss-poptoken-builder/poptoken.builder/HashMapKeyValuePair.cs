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

using System.Collections.Generic;

namespace com.tmobile.oss.security.taap.poptoken.builder
{
	/// <summary>
	/// HashMap KeyValuePair
	/// </summary>
	public static class HashMapKeyValuePair
	{
		/// <summary>
		/// Get KeyValuePair
		/// </summary>
		/// <typeparam name="K">key</typeparam>
		/// <typeparam name="V">value</typeparam>
		/// <param name="dictionary">dictionary</param>
		/// <param name="key">key</param>
		/// <returns>keyValuePair</returns>
		public static V Get<K, V>(this IDictionary<K, V> dictionary, K key)
		{
			V keyValuePair;
			dictionary.TryGetValue(key, out keyValuePair);

			return keyValuePair;
		}

		/// <summary>
		/// Set HashSet KeyValuePair
		/// </summary>
		/// <typeparam name="K">key</typeparam>
		/// <typeparam name="V">value</typeparam>
		/// <param name="dictionary"></param>
		/// <returns>HashSet KeyValuePair</returns>
		public static HashSet<KeyValuePair<K, V>> Set<K, V>(this IDictionary<K, V> dictionary)
		{
			var keyValuePairHashSet = new HashSet<KeyValuePair<K, V>>();
			foreach (var keyValuePair in dictionary)
			{
				keyValuePairHashSet.Add(keyValuePair);
			}

			return keyValuePairHashSet;
		}
	}
}
