## This SMB is used to further "Set up" the session normally just
## established via the negotiate protocol.
##
## One primary function is to perform a "user logon" in the case
## where the server is in user level security mode. The UID in the
## SMB header is set by the client to by the userid desired for the
## AccountName and validated by the AccountPassword.

refine connection SMB_Conn += {

	function proc_smb1_session_setup_andx_request(header: SMB_Header, val: SMB1_session_setup_andx_request): bool
		%{
		if ( smb1_session_setup_andx_request )
			{
			RecordVal* request = new RecordVal(BifType::Record::SMB1::SessionSetupAndXRequest);
			RecordVal* capabilities;
			
			request->Assign(0, new Val(${val.word_count}, TYPE_COUNT));
			switch ( ${val.word_count} ) {
				case 10:	// pre NT LM 0.12
					request->Assign(1, new Val(${val.lanman.max_buffer_size}, TYPE_COUNT));
					request->Assign(2, new Val(${val.lanman.max_mpx_count}, TYPE_COUNT));
					request->Assign(3, new Val(${val.lanman.vc_number}, TYPE_COUNT));
					request->Assign(4, new Val(${val.lanman.session_key}, TYPE_COUNT));

					request->Assign(5, smb_string2stringval(${val.lanman.native_os}));
					request->Assign(6, smb_string2stringval(${val.lanman.native_lanman}));
					request->Assign(7, smb_string2stringval(${val.lanman.account_name}));
					request->Assign(8, bytestring_to_val(${val.lanman.account_password}));
					request->Assign(9, smb_string2stringval(${val.lanman.primary_domain}));

					break;
				case 12:	// NT LM 0.12 with extended security
					capabilities = new RecordVal(BifType::Record::SMB1::SessionSetupAndXCapabilities);
				 	capabilities->Assign(0, new Val(${val.ntlm_extended_security.capabilities.unicode}, TYPE_BOOL));
				 	capabilities->Assign(1, new Val(${val.ntlm_extended_security.capabilities.large_files}, TYPE_BOOL));
				 	capabilities->Assign(2, new Val(${val.ntlm_extended_security.capabilities.nt_smbs}, TYPE_BOOL));
				 	capabilities->Assign(3, new Val(${val.ntlm_extended_security.capabilities.status32}, TYPE_BOOL));
				 	capabilities->Assign(4, new Val(${val.ntlm_extended_security.capabilities.level_2_oplocks}, TYPE_BOOL));
				 	capabilities->Assign(5, new Val(${val.ntlm_extended_security.capabilities.nt_find}, TYPE_BOOL));
				
					request->Assign(1, new Val(${val.ntlm_extended_security.max_buffer_size}, TYPE_COUNT));
					request->Assign(2, new Val(${val.ntlm_extended_security.max_mpx_count}, TYPE_COUNT));
					request->Assign(3, new Val(${val.ntlm_extended_security.vc_number}, TYPE_COUNT));
					request->Assign(4, new Val(${val.ntlm_extended_security.session_key}, TYPE_COUNT));

					request->Assign(5, smb_string2stringval(${val.ntlm_extended_security.native_os}));
					request->Assign(6, smb_string2stringval(${val.ntlm_extended_security.native_lanman}));

					//request->Assign(12, bytestring_to_val(${val.ntlm_extended_security.security_blob}));
					request->Assign(13, capabilities);
					break;
					
				case 13:	// NT LM 0.12 without extended security
					capabilities = new RecordVal(BifType::Record::SMB1::SessionSetupAndXCapabilities);
				 	capabilities->Assign(0, new Val(${val.ntlm_nonextended_security.capabilities.unicode}, TYPE_BOOL));
				 	capabilities->Assign(1, new Val(${val.ntlm_nonextended_security.capabilities.large_files}, TYPE_BOOL));
				 	capabilities->Assign(2, new Val(${val.ntlm_nonextended_security.capabilities.nt_smbs}, TYPE_BOOL));
				 	capabilities->Assign(3, new Val(${val.ntlm_nonextended_security.capabilities.status32}, TYPE_BOOL));
				 	capabilities->Assign(4, new Val(${val.ntlm_nonextended_security.capabilities.level_2_oplocks}, TYPE_BOOL));
				 	capabilities->Assign(5, new Val(${val.ntlm_nonextended_security.capabilities.nt_find}, TYPE_BOOL));
				
					request->Assign(1, new Val(${val.ntlm_nonextended_security.max_buffer_size}, TYPE_COUNT));
					request->Assign(2, new Val(${val.ntlm_nonextended_security.max_mpx_count}, TYPE_COUNT));
					request->Assign(3, new Val(${val.ntlm_nonextended_security.vc_number}, TYPE_COUNT));
					request->Assign(4, new Val(${val.ntlm_nonextended_security.session_key}, TYPE_COUNT));

					request->Assign(5, smb_string2stringval(${val.ntlm_nonextended_security.native_os}));
					request->Assign(6, smb_string2stringval(${val.ntlm_nonextended_security.native_lanman}));
					request->Assign(7, smb_string2stringval(${val.ntlm_nonextended_security.account_name}));
					request->Assign(9, smb_string2stringval(${val.ntlm_nonextended_security.primary_domain}));

					request->Assign(10, bytestring_to_val(${val.ntlm_nonextended_security.case_insensitive_password}));
					request->Assign(11, bytestring_to_val(${val.ntlm_nonextended_security.case_sensitive_password}));
					request->Assign(13, capabilities);
					break;
				}

			BifEvent::generate_smb1_session_setup_andx_request(bro_analyzer(), bro_analyzer()->Conn(), BuildHeaderVal(header), request);
			}
		return true;
		%}
		
	function proc_smb1_session_setup_andx_response(header: SMB_Header, val: SMB1_session_setup_andx_response): bool
		%{
		if ( smb1_session_setup_andx_response )
			{
			RecordVal* response = new RecordVal(BifType::Record::SMB1::SessionSetupAndXResponse);

			response->Assign(0, new Val(${val.word_count}, TYPE_COUNT));
			switch ( ${val.word_count} )
				{
				case 3:		// pre NT LM 0.12
					response->Assign(1, new Val(${val.lanman.is_guest}, TYPE_BOOL));
					response->Assign(2, smb_string2stringval(${val.lanman.native_os}));
					response->Assign(3, smb_string2stringval(${val.lanman.native_lanman}));
					response->Assign(4, smb_string2stringval(${val.lanman.primary_domain}));
					break;
				case 4:		// NT LM 0.12
					response->Assign(1, new Val(${val.ntlm.is_guest}, TYPE_BOOL));
					response->Assign(2, smb_string2stringval(${val.ntlm.native_os}));
					response->Assign(3, smb_string2stringval(${val.ntlm.native_lanman}));
					response->Assign(4, smb_string2stringval(${val.ntlm.primary_domain}));
					//response->Assign(5, bytestring_to_val(${val.ntlm.security_blob}));
					break;
				default:		// Error!
					break;
				}
			
			BifEvent::generate_smb1_session_setup_andx_response(bro_analyzer(), bro_analyzer()->Conn(), BuildHeaderVal(header), response);
			}
		
		return true;
		%}

};

type SMB1_session_setup_andx_request(header: SMB_Header) = record {
	word_count       : uint8;
	lanman_or_ntlm	 : case word_count of {
		0x0a -> lanman: SMB1_session_setup_andx_request_lanman(header);
		0x0c -> ntlm_extended_security: SMB1_session_setup_andx_request_ntlm_extended_security(header);
		0x0d -> ntlm_nonextended_security: SMB1_session_setup_andx_request_ntlm_nonextended_security(header);
	};
} &let {
	proc: bool = $context.connection.proc_smb1_session_setup_andx_request(header, this);
};

type SMB1_session_setup_andx_response(header: SMB_Header) = record {
	word_count       : uint8;
	lanman_or_ntlm	 : case word_count of {
		0x03    -> lanman: SMB1_session_setup_andx_response_lanman(header);
		0x04    -> ntlm: SMB1_session_setup_andx_response_ntlm(header);
		default -> error: uint16;
	};
} &let {
	proc: bool = $context.connection.proc_smb1_session_setup_andx_response(header, this);
};

type SMB1_session_setup_andx_request_lanman(header: SMB_Header) = record {
	andx		 : SMB_andx;
	max_buffer_size	 : uint16;
	max_mpx_count	 : uint16;
	vc_number	 : uint16;
	session_key	 : uint32;
	password_length	 : uint16;
	reserved	 : uint32;
	byte_count	 : uint16;
	account_password : bytestring &length=password_length;
	# offset + 1 due to word_count in the parent type
	account_name	 : SMB_string(header.unicode, offsetof(account_name) + 1);
	primary_domain	 : SMB_string(header.unicode, offsetof(primary_domain) + 1);
	native_os	 : SMB_string(header.unicode, offsetof(native_os) + 1);
	native_lanman	 : SMB_string(header.unicode, offsetof(native_lanman) + 1);
};

type SMB1_session_setup_andx_response_lanman(header: SMB_Header) = record {
	andx	       : SMB_andx;
	action	       : uint16;
	byte_count     : uint16;
	# offset + 1 due to word_count in the parent type
	native_os      : SMB_string(header.unicode, offsetof(native_os) + 1);
	native_lanman  : SMB_string(header.unicode, offsetof(native_lanman) + 1);
	primary_domain : SMB_string(header.unicode, offsetof(primary_domain) + 1);
} &let {
	is_guest: bool = ( action & 0x1 ) > 0;
};

type SMB1_session_setup_andx_request_ntlm_capabilities = record {
	capabilities	                 : uint32;
} &let {
	unicode         : bool = ( capabilities & 0x0004 ) > 0;
	large_files     : bool = ( capabilities & 0x0008 ) > 0;
	nt_smbs         : bool = ( capabilities & 0x0010 ) > 0;
	status32        : bool = ( capabilities & 0x0040 ) > 0;
	level_2_oplocks : bool = ( capabilities & 0x0080 ) > 0;
	nt_find		: bool = ( capabilities & 0x0200 ) > 0;
};

type SMB1_session_setup_andx_request_ntlm_nonextended_security(header: SMB_Header) = record {
	andx		                 : SMB_andx;
	max_buffer_size	                 : uint16;
	max_mpx_count	                 : uint16;
	vc_number	                 : uint16;
	session_key	                 : uint32;
	case_insensitive_password_length : uint16;
	case_sensitive_password_length   : uint16;
	reserved	                 : uint32;
	capabilities			 : SMB1_session_setup_andx_request_ntlm_capabilities;
	byte_count	                 : uint16;
	case_insensitive_password        : bytestring &length=case_insensitive_password_length;
	case_sensitive_password          : bytestring &length=case_sensitive_password_length;
	# offset + 1 due to word_count in the parent type
	account_name			 : SMB_string(header.unicode, offsetof(account_name) + 1);
	primary_domain			 : SMB_string(header.unicode, offsetof(primary_domain) + 1);
	native_os	                 : SMB_string(header.unicode, offsetof(native_os) + 1);
	native_lanman	                 : SMB_string(header.unicode, offsetof(native_lanman) + 1);
};

type SMB1_session_setup_andx_request_ntlm_extended_security(header: SMB_Header) = record {
	andx		          : SMB_andx;
	max_buffer_size	          : uint16;
	max_mpx_count	          : uint16;
	vc_number	          : uint16;
	session_key	          : uint32;
	security_blob_length	  : uint16;
	reserved	          : uint32;
	capabilities	          : SMB1_session_setup_andx_request_ntlm_capabilities;
	byte_count	          : uint16;
	security_blob		  : SMB_NTLM_SSP(header) &length=security_blob_length;
	# offset + 1 due to word_count in the parent type
	native_os	          : SMB_string(header.unicode, offsetof(native_os) + 1);
	native_lanman	          : SMB_string(header.unicode, offsetof(native_lanman) + 1);
};

type SMB1_session_setup_andx_response_ntlm(header: SMB_Header) = record {
	andx		     : SMB_andx;
	action		     : uint16;
	security_blob_length : uint16;
	byte_count	     : uint16;
	security_blob	     : SMB_NTLM_SSP(header) &length=security_blob_length;
	# offset + 1 due to word_count in the parent type
	native_os	     : SMB_string(header.unicode, offsetof(native_os) + 1);
	native_lanman	     : SMB_string(header.unicode, offsetof(native_lanman) + 1);
	primary_domain	     : SMB_string(header.unicode, offsetof(primary_domain) + 1);
} &let {
	is_guest: bool = ( action & 0x1 ) > 0;
};

