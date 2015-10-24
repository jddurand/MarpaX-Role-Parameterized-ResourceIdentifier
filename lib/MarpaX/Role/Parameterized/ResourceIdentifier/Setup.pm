use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::Setup;
use Moo;
with 'MooX::Singleton';
use Types::Standard -all;

# ABSTRACT: Resource Identifier setup

# VERSION

# AUTHORITY

our $MARPA_TRACE_TERMINALS = ($ENV{'MarpaX__ResourceIdentifier__MARPA_TRACE_TERMINALS'} // 0) ? 1 : 0;
our $MARPA_TRACE_VALUES    = ($ENV{'MarpaX__ResourceIdentifier__MARPA_TRACE_VALUES'}    // 0) ? 1 : 0;
our $MARPA_TRACE           = $MARPA_TRACE_TERMINALS || $MARPA_TRACE_VALUES;
our $WITH_LOGGER           = (($ENV{'MarpaX__ResourceIdentifier__WITH_LOGGER'}          // 0) || $MARPA_TRACE) ? 1 : 0;
our $URI_COMPAT            = ($ENV{'MarpaX__ResourceIdentifier__URI_COMPAT'} // 0) ? 1 : 0;

has marpa_trace_terminals => ( is => 'ro', isa => Bool, default => sub { $MARPA_TRACE_TERMINALS } );
has marpa_trace_values    => ( is => 'ro', isa => Bool, default => sub { $MARPA_TRACE_VALUES    } );
has marpa_trace           => ( is => 'ro', isa => Bool, default => sub { $MARPA_TRACE           } );
has with_logger           => ( is => 'ro', isa => Bool, default => sub { $WITH_LOGGER           } );
has uri_compat            => ( is => 'ro', isa => Bool, default => sub { $URI_COMPAT            } );

1;
