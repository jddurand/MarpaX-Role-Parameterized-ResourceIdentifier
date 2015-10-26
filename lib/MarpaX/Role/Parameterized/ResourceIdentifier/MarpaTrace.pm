use strict;
use warnings FATAL => 'all';

package MarpaX::Role::Parameterized::ResourceIdentifier::MarpaTrace;

# ABSTRACT: Marpa Trace Wrapper

# VERSION

# AUTHORITY

sub BEGIN {
  #
  ## Some Log implementation specificities
  #
  my $log4perl = eval 'use Log::Log4perl; 1;' || 0; ## no critic
  if ($log4perl) {
    #
    ## Here we put know hooks for logger implementations
    #
    Log::Log4perl->wrapper_register(__PACKAGE__);
  }
}

sub TIEHANDLE {
  my $class = shift;
  my $category = $MarpaX::Role::Parameterized::ResourceIdentifier::MarpaTrace::bnf_package || __PACKAGE__;
  bless { category => $category, logger => Log::Any->get_logger(category => $category) }, $class;
}

sub PRINT {
  my $self = shift;
  #
  # We do not want to be perturbed by automatic thingies coming from $\
  #
  local $\ = undef;
  map { $self->{logger}->tracef('%s: %s', $self->{category}, $_) } split(/\n/, join('', @_));
  return 1;
}

sub PRINTF {
  shift->PRINT(sprintf(shift, @_));
  return 1;
}

1;
