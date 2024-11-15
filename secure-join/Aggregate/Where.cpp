#include "Where.h"

namespace secJoin {

	// add the evaluation of `cir` to the `parent` circuit where
	// `inputs` are the input wires to the circuit and 
	// `outputs` are the output wires.
	void evaluate(oc::BetaCircuit& parent, const oc::BetaCircuit& cir, span<BetaBundle> inputs, span<BetaBundle> outputs)
	{
		if (cir.mInputs.size() != inputs.size())
			throw std::runtime_error(LOCATION);
		if (cir.mOutputs.size() != outputs.size())
			throw std::runtime_error(LOCATION);

		// count the number of internal wires in the circuit.
		u64 tempCount = cir.mWireCount;
		for (u64 i = 0; i < inputs.size(); i++)
		{
			if (cir.mInputs[i].size() != inputs[i].size())
				throw std::runtime_error(LOCATION);

			tempCount -= inputs[i].size();
		}

		for (u64 i = 0; i < outputs.size(); i++)
		{
			if (cir.mOutputs[i].size() != outputs[i].size())
				throw std::runtime_error(LOCATION);

			tempCount -= outputs[i].size();
		}

		// allocate the internal wires
		oc::BetaBundle temp(tempCount);
		parent.addTempWireBundle(temp);

		// flatten all the wires for cir into an array.
		oc::BetaBundle wires(cir.mWireCount);
		for (u64 i = 0; i < inputs.size(); i++)
		{
			for (u64 j = 0; j < inputs[i].size(); j++)
				wires[cir.mInputs[i][j]] = inputs[i][j];
		}
		for (u64 i = 0; i < outputs.size(); i++)
			for (u64 j = 0; j < outputs[i].size(); j++)
				wires[cir.mOutputs[i][j]] = outputs[i][j];
		for (u64 i = 0; i < temp.size(); i++)
			wires[i + cir.mWireCount - tempCount] = temp[i];

		// evaluate the circuit.
		for (u64 i = 0; i < cir.mGates.size(); i++)
		{
			auto& gate = cir.mGates[i];
			auto& in0 = wires[gate.mInput[0]];
			auto& in1 = wires[gate.mInput[1]];
			auto& out = wires[gate.mOutput];
			if (gate.mType == oc::GateType::a)
				parent.addCopy(in0, out);
			else
				parent.addGate(in0, in1, gate.mType, out);
		}
	}

	// given cir, we add an additional input which is the isActive flag.
	// the final output is the output of cir & isActive.
	oc::BetaCircuit Where::makeWhereClause(const oc::BetaCircuit& cir)
	{
		if (cir.mOutputs.size() != 1)
			throw std::runtime_error(LOCATION);

		oc::BetaCircuit whereClause;
		std::vector<BetaBundle> inputs(cir.mInputs.size());
		for (u64 i = 0; i < cir.mInputs.size(); i++)
		{
			inputs[i].resize(cir.mInputs[i].size());
			whereClause.addInputBundle(inputs[i]);
		}

		BetaBundle isActive(1);
		whereClause.addInputBundle(isActive);

		BetaBundle output(1);	
		whereClause.addOutputBundle(output);

		BetaBundle temp(1);
		whereClause.addTempWireBundle(temp);

		// add { temp = cir(inputs) } to `whereClause`.
		evaluate(whereClause, cir, inputs, { &temp, 1 });

		// add { output = temp & isActive } to `whereClause`.
		whereClause.addGate(temp.mWires[0], isActive.mWires[0], oc::GateType::And, output.mWires[0]);

		return whereClause;
	}

	void Where::init(
		u64 rows,
		span<ColumnInfo> columns,
		span<u64> whereInputs,
		oc::BetaCircuit& cir,
		CorGenerator& ole,
		bool remDummiesFlag)
	{
		if (cir.mInputs.size() != whereInputs.size())
			throw std::runtime_error(LOCATION);	
		if (cir.mOutputs.size() != 1)
			throw std::runtime_error(LOCATION);
		for (auto i : oc::rng(whereInputs.size()))
		{
			if (whereInputs[i] >= columns.size())
				throw std::runtime_error(LOCATION);
			if (columns[whereInputs[i]].mBitCount != cir.mInputs[i].size())
				throw std::runtime_error(LOCATION);
		}

		mRows = rows;
		mWhereInputs = std::vector<u64>(whereInputs.begin(), whereInputs.end());
		mWhereClauseCir = makeWhereClause(cir);
		mGmw.init(rows, mWhereClauseCir, ole);
		for (auto i : oc::rng(whereInputs.size()))
			mColumns.push_back(columns[whereInputs[i]]);

		if (remDummiesFlag)
		{
			u64 bytesPerRow = 1; // is active flag
			for (u64 i = 0; i < whereInputs.size(); i++)
				bytesPerRow += columns[i].getByteCount();
			mRemoveInactive.emplace(rows, bytesPerRow, ole);
		}
	}

	macoro::task<> Where::where(
		const Table& input,
		Table& output,
		coproto::Socket& sock,
		PRNG& prng)
	{
		if (input.mColumns.size() != mColumns.size())
			throw RTE_LOC;
		if(input.rows() != mRows)
			throw RTE_LOC;
		for (auto i : oc::rng(input.mColumns.size()))
			if (input.mColumns[i] != mColumns[i])
				throw std::runtime_error(LOCATION);

		// set the inputs
		mGmw.setInput(mWhereInputs.size(), matrixCast<u8>(input.mIsActive));
		for (auto i : oc::rng(mWhereInputs.size()))
			mGmw.setInput(i, input.mColumns[mWhereInputs[i]].mData);

		mGmw.mDebugPrintIdx = 13;
		// eval the where clause and AND with the isActive flag.
		co_await mGmw.run(sock);

		// copy the output
		if (&input != &output)
			output = input;

		// update the isActive flag with the output of the where clause.
		output.mIsActive.resize(mRows);
		mGmw.getOutput(0, matrixCast<u8>(output.mIsActive));

		// optionall remove inactive rows.
		if (mRemoveInactive)
		{
			co_await mRemoveInactive->apply(output, output, sock, prng);
		}
	}



}