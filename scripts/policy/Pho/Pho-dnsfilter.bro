event bro_init()
{
    Log::remove_default_filter(DNS::LOG);
    Log::add_filter(DNS::LOG, [
        $name = "Pho-dns-filter",
        $pred(rec: DNS::Info) = {
            if (rec?$query && /.in-addr.arpa/ in rec$query)
                return F;
            if (rec?$qtype_name && /NB/ in rec$qtype_name)
                return F;
            if (rec?$query && /WPAD/ in rec$query)
                return F;
            
            # Filter out internal lookups
            
            #if (rec?$query && /mydomain.com/ in rec$query)
            #    return F;
            }
    ]);
}
