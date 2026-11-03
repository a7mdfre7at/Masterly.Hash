using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Operations;

namespace Masterly.Hash.Analyzers.Internal
{
    internal static class OperationHelpers
    {
        /// <summary>True if the compilation references <c>Masterly.Hash.Password.Hash(string)</c> returning <c>string</c>.</summary>
        public static bool HasPasswordHash(Compilation compilation)
        {
            INamedTypeSymbol? password = compilation.GetTypeByMetadataName("Masterly.Hash.Password");
            return password != null && password.GetMembers("Hash").OfType<IMethodSymbol>().Any(m =>
                m.IsStatic
                && m.DeclaredAccessibility == Accessibility.Public
                && m.Parameters.Length == 1
                && m.Parameters[0].Type.SpecialType == SpecialType.System_String
                && m.ReturnType.SpecialType == SpecialType.System_String);
        }

        /// <summary>Strips implicit and explicit conversions.</summary>
        public static IOperation Unwrap(IOperation operation)
        {
            while (operation is IConversionOperation conversion)
                operation = conversion.Operand;
            return operation;
        }

        /// <summary>The variable, member or method an expression directly refers to, if any.</summary>
        public static ISymbol? GetReferencedSymbol(IOperation operation)
        {
            switch (Unwrap(operation))
            {
                case ILocalReferenceOperation local: return local.Local;
                case IParameterReferenceOperation parameter: return parameter.Parameter;
                case IFieldReferenceOperation field: return field.Field;
                case IPropertyReferenceOperation property: return property.Property;
                case IInvocationOperation invocation: return invocation.TargetMethod;
                default: return null;
            }
        }

        /// <summary>Type of a symbol returned by <see cref="GetReferencedSymbol"/>.</summary>
        public static ITypeSymbol? GetSymbolType(ISymbol symbol)
        {
            switch (symbol)
            {
                case ILocalSymbol local: return local.Type;
                case IParameterSymbol parameter: return parameter.Type;
                case IFieldSymbol field: return field.Type;
                case IPropertySymbol property: return property.Type;
                case IMethodSymbol method: return method.ReturnType;
                default: return null;
            }
        }

        /// <summary>The operation and all of its descendants, skipping <c>nameof(...)</c>, whose value is a constant name.</summary>
        public static IEnumerable<IOperation> DescendantsAndSelf(IOperation root)
        {
            var stack = new Stack<IOperation>();
            stack.Push(root);
            while (stack.Count > 0)
            {
                IOperation current = stack.Pop();
                if (current is INameOfOperation)
                    continue;
                yield return current;
                foreach (IOperation child in current.ChildOperations)
                    stack.Push(child);
            }
        }

        /// <summary>True for <c>null</c>, <c>default</c>, <c>""</c> and <c>string.Empty</c>.</summary>
        public static bool IsNullOrEmptyConstant(IOperation operation)
        {
            if (operation.ConstantValue.HasValue)
            {
                object? value = operation.ConstantValue.Value;
                return value is null || (value is string s && s.Length == 0);
            }

            IOperation inner = Unwrap(operation);
            if (inner.ConstantValue.HasValue)
            {
                object? value = inner.ConstantValue.Value;
                return value is null || (value is string s && s.Length == 0);
            }

            switch (inner)
            {
                case IDefaultValueOperation _:
                    return true;
                case IFieldReferenceOperation field:
                    return field.Field.Name == "Empty" && field.Field.ContainingType?.SpecialType == SpecialType.System_String;
                case IInvocationOperation invocation:
                    return invocation.TargetMethod.Name == "Empty"
                        && invocation.TargetMethod.ContainingType?.SpecialType == SpecialType.System_Array;
                default:
                    return false;
            }
        }

        public static bool IsType(ITypeSymbol? type, INamedTypeSymbol? expected) =>
            type != null && expected != null && SymbolEqualityComparer.Default.Equals(type.OriginalDefinition, expected);

        public static bool DerivesFrom(ITypeSymbol? type, INamedTypeSymbol? baseType)
        {
            if (baseType == null)
                return false;
            for (ITypeSymbol? current = type; current != null; current = current.BaseType)
            {
                if (SymbolEqualityComparer.Default.Equals(current.OriginalDefinition, baseType))
                    return true;
            }

            return false;
        }

        public static bool IsByteArray(ITypeSymbol? type) =>
            type is IArrayTypeSymbol array && array.Rank == 1 && array.ElementType.SpecialType == SpecialType.System_Byte;

        /// <summary>True for <c>Encoding.X.GetBytes(string)</c> with exactly one argument.</summary>
        public static bool IsEncodingGetBytes(IInvocationOperation invocation, INamedTypeSymbol? encoding) =>
            encoding != null
            && invocation.TargetMethod.Name == "GetBytes"
            && invocation.Arguments.Length == 1
            && invocation.Arguments[0].Value.Type?.SpecialType == SpecialType.System_String
            && DerivesFrom(invocation.TargetMethod.ContainingType, encoding);
    }
}
