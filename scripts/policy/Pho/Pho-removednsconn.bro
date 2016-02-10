# Removes conn log events that are actually DNS from the conn_log. This is helpful when you are in front of a large DNS farm.

@load base/protocols/conn

event bro_init()
        {
        local filt = Log::get_filter(Conn::LOG, "default");
        filt$pred = function(rec: Conn::Info): bool
                {
                        return (! rec?$service || rec$service != "dns");
                };
        Log::add_filter(Conn::LOG, filt);
        }
