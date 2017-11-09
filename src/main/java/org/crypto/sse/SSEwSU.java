/** * Copyright (C) 2017 Nick Cunningham and Sorin Vatasoiu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.crypto.sse;

import java.io.Serializable;

public class SSEwSU {
	
	class Server implements Serializable {
	
		//state: set of encrypted documents
		//some kind of keys for searching
		//authorization set
		
		//public lotsofkeydataformanager Setup(Set<Document);
		//public Set<Document> SearchReply(qSet); (takes query ciphertexts from SearchQuery)
		//AuthComputingUpdate: takes some output from AuthComputing and updates data to reflect new access permissions
		
	}
	
	class Manager {
		
		//state: 3 master keys {0, 1}^lambda
		//maybe index for document ids to share
		
		//constructor: takes lotsofkeydataformanager from server setup
		//public UserKeys Enroll(user)
		//AuthComputing: share d with u; takes user+user's keys, document id d, master keys (in manager state); sends result to server
		
	}
	
	class User {
		
		//state: id
		//two user keys {0, 1}^lambda
		//keys for documents shared
		
		//constructor: takes UserKeys from manager Enroll
		//SearchQuery: produce set of query ciphertexts for keyword w on all documents user accesses
		//AuthComputingUpdate: takes some output from AuthComputing and updates data to allow access
	}

}
