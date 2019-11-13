
def run_tests(ipa, r2, u, r2h):
	u.test(ipa, r2h.has_import(r2, ["__stack_chk_guard", "_stack_chk_guard", "stack_chk_guard"]), "Stack smashing protection (-fstack-protector-all)", "MISSING", 5)
	u.test(ipa, r2h.has_import(r2, ["objc_autorelease"]), "Objective-C automatic reference counting (-fobjc-arc)", "MISSING", 5)
	u.test(ipa, r2h.has_info(r2, "pic"), "Full ASLR (-pie)", "MISSING", 5)

def name_test():
	return "Detection Compiler flags"