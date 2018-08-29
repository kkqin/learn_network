#include <regex.h>

char * 
regex_get_url(char * original)
{
	regex_t regex;
	size_t nmatch = 2;
	regmatch_t pmatch[2];

	int reti = regcomp(&regex, "(([a-zA-Z0-9_\\.])+\\.([a-zA-Z0-9_])+){1,3}", REG_EXTENDED);
	if(reti)
	{
		printf("error regex");
		return NULL;	
	}

	reti = regexec(&regex, original, nmatch, pmatch, 0);
	if(!reti)
	{
		printf("regex after:%.*s\n", pmatch[1].rm_eo - pmatch[1].rm_so, &original[pmatch[1].rm_so]);
		regfree(&regex);

		//printf("sss: %s", &original[pmatch[1].rm_so]);
		
		return &original[pmatch[1].rm_so];	
	}

	printf("error regex");
	regfree(&regex);
	return NULL; 	
}

