package adcs

// hresultHint maps common CERTSRV_E_* HRESULTs (winerror.h) that a CA policy
// module returns to a plain-English cause. Unknown codes return "".
func hresultHint(code uint32) string {
	switch code {
	case 0x80094011:
		return "the CA does not allow this account to enroll"
	case 0x80094012:
		return "template permissions do not allow this account to enroll"
	case 0x80094800:
		return "the template is not published on this CA"
	case 0x80094801:
		return "the request does not name a certificate template"
	case 0x80094803:
		return "the template requires a subject alternative name"
	case 0x8009480D:
		return "the template builds the subject from Active Directory (UPN required); set it to supply in the request"
	case 0x8009480F:
		return "the template builds the subject from Active Directory (DNS name required); set it to supply in the request"
	case 0x80094812:
		return "the template builds the subject from Active Directory (email required); set it to supply in the request"
	case 0x80094811:
		return "the key length is below the template minimum"
	case 0x80094813:
		return "the CA does not recognize the template"
	}
	return ""
}
