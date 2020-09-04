//
// Created by nova on 8/2/20.
//

#include "DNS.h"
#include "CloudflareImpl.h"

const std::vector<std::string>& DNS::SupportedProviders()
{
	static std::vector<std::string> providers
	{
		"cloudflare"
	};
	return providers;
}

bool DNS::ProviderIsSupported(const std::string& providerName)
{
	std::string copy = Utils::StringProcess::ToLowerCase(providerName);
	for (const auto& name : SupportedProviders())
	{
		if (name == copy)
			return true;
	}
	return false;
}

std::shared_ptr<DNS::API> DNS::API::create(const std::string& providerName, const Json::Value& apiParams)
{
	std::string lowerCase = Utils::StringProcess::ToLowerCase(providerName);
	if ( !DNS::ProviderIsSupported(lowerCase) )
		throw ProviderNotSupportedException("dns provider '" + providerName + "' not supported");
	else if ( lowerCase == "cloudflare" )
		return std::make_shared<DNS::CloudflareImpl>(apiParams);
	else
		return nullptr;
}
