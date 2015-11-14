use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Setup;
use Moo;
use Types::Standard -all;

# ABSTRACT: Resource Identifier setup

# VERSION

# AUTHORITY

sub marpa_trace_terminals   {($ENV{'MarpaX_RI_MARPA_TRACE_TERMINALS'}   // 0) ? 1 : 0   }
sub marpa_trace_values      {($ENV{'MarpaX_RI_MARPA_TRACE_VALUES'}      // 0) ? 1 : 0   }
sub uri_compat              { $ENV{'MarpaX_RI_URI_COMPAT'}              // 1            }
sub plugins_dirname         { $ENV{'MarpaX_RI_PLUGINS_DIRNAME'}         // 'Plugins'    }
sub can_scheme_methodname   { $ENV{'MarpaX_RI_CAN_SCHEME_METHODNAME'}   // 'can_scheme' }
sub abs_remote_leading_dots { $ENV{'MarpaX_RI_ABS_REMOTE_LEADING_DOTS'} // 0            }

with 'MooX::Singleton';

1;
