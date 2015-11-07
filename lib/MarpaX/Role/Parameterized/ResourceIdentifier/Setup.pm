use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Setup;
use Moo;
with 'MooX::Singleton';
use Types::Standard -all;

# ABSTRACT: Resource Identifier setup

# VERSION

# AUTHORITY

our $MARPA_TRACE_TERMINALS = ($ENV{'MarpaX_RI_MARPA_TRACE_TERMINALS'} // 0) ? 1 : 0;
our $MARPA_TRACE_VALUES    = ($ENV{'MarpaX_RI_MARPA_TRACE_VALUES'}    // 0) ? 1 : 0;
our $URI_COMPAT            = ($ENV{'MarpaX_RI_URI_COMPAT'}            // 1);
our $PLUGINS_DIRNAME       = ($ENV{'MarpaX_RI_PLUGINS_DIRNAME'}       // 'Plugins');
our $CAN_SCHEME_METHODNAME = ($ENV{'MarpaX_RI_CAN_SCHEME_METHODNAME'} // 'can_scheme');

has marpa_trace_terminals => ( is => 'ro', isa => Bool, default => sub { $MARPA_TRACE_TERMINALS } );
has marpa_trace_values    => ( is => 'ro', isa => Bool, default => sub { $MARPA_TRACE_VALUES    } );
has uri_compat            => ( is => 'ro', isa => Bool, default => sub { $URI_COMPAT            } );
has plugins_dirname       => ( is => 'ro', isa => Str,  default => sub { $PLUGINS_DIRNAME       } );
has can_scheme_methodname => ( is => 'ro', isa => Str,  default => sub { $CAN_SCHEME_METHODNAME } );

1;
