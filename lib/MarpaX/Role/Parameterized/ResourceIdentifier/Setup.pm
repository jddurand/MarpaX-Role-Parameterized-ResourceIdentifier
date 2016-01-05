use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Setup;
use Moo;
use Types::Standard -all;

# ABSTRACT: Resource Identifier setup

# VERSION

# AUTHORITY

no warnings 'once';
#
# The followings have a default value
#
sub marpa_trace_terminals      { $MarpaX::RI::MARPA_TRACE_TERMINALS   // 0            }
sub marpa_trace_values         { $MarpaX::RI::MARPA_TRACE_VALUES      // 0            }
sub plugins_dirname            { $MarpaX::RI::PLUGINS_DIRNAME         || 'Plugins'    }
sub impl_dirname               { $MarpaX::RI::IMPL_DIRNAME            || 'Impl'       }
sub can_scheme_methodname      { $MarpaX::RI::CAN_SCHEME_METHODNAME   || 'can_scheme' }
#
# The followings can return undef
#
sub abs_remote_leading_dots             {   $MarpaX::RI::ABS_REMOTE_LEADING_DOTS                }
sub abs_normalized_base                 {   $MarpaX::RI::ABS_NORMALIZED_BASE                    }
sub rel_normalized                      {   $MarpaX::RI::REL_NORMALIZED                         }
sub remove_dot_segments_strict          { ! $MarpaX::RI::ABS_ALLOW_RELATIVE_SCHEME              }
sub default_query_form_delimiter        {   $MarpaX::RI::DEFAULT_QUERY_FORM_DELIMITER    || '&' }
sub default_segment_parameter_delimiter {   $MarpaX::RI::DEFAULT_QUERY_FORM_DELIMITER    || ';' }
sub default_user_password_delimiter     {   $MarpaX::RI::DEFAULT_USER_PASSWORD_DELIMITER || ':' }

with 'MooX::Singleton';

1;
